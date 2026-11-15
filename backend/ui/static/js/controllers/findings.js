document.addEventListener("alpine:init", () => {
  const LIST_LIMIT = 100;
  const IMPORT_BATCH = 100;
  const DEFAULT_DISCOVERED_BY = "Unassigned";
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const SEVERITY_RANK = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  };
  const STATUS_ORDER = [
    "open",
    "remediated",
    "risk_accepted",
    "false_positive",
  ];
  const FINDING_STATUSES = [
    "open",
    "remediated",
    "risk_accepted",
    "false_positive",
  ];
  const SEVERITY_ABBREV = {
    critical: "CRIT",
    high: "HIGH",
    medium: "MED",
    low: "LOW",
    info: "INFO",
  };
  const SEVERITY_LABELS = {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    info: "Info",
  };
  const IMPORT_SCHEMA_SAMPLE = `[
  {
    "title": "SQL Injection in Authentication Endpoint",
    "severity": "critical",
    "asset_name": "https://api.corp.internal/v1/auth",
    "description": "…",
    "recommendation": "…",
    "evidence": {
      "packages": [
        {
          "type": "http",
          "items": [
            { "label": "Request", "content": "POST /v1/auth …" },
            { "label": "Response", "content": "HTTP/1.1 200 …" }
          ]
        }
      ]
    }
  }
]`;

  const SEVERITY_DESC = {
    critical: "Immediate risk of full compromise, data breach, or remote code execution.",
    high: "Serious impact with a realistic path to privilege escalation or sensitive access.",
    medium: "Meaningful risk that usually needs chaining or limited attacker conditions.",
    low: "Limited impact; useful hardening signal but unlikely to be exploited alone.",
    info: "No direct exploit path. Observation for awareness, hygiene, or future context.",
  };

  function normalizeSeverity(value, fallback = "medium") {
    const key = String(value || "").toLowerCase().trim();
    return SEVERITIES.includes(key) ? key : fallback;
  }

  function severityRank(value) {
    return SEVERITY_RANK[normalizeSeverity(value, "")] || 0;
  }

  function statusRank(value) {
    const index = STATUS_ORDER.indexOf(String(value || "").toLowerCase());
    return index === -1 ? STATUS_ORDER.length : index;
  }

  const SORT_ACCESSORS = {
    severity: (f) => severityRank(f.severity),
    title: (f) => String(f.title || "").toLowerCase(),
    targetAsset: (f) => String(f.asset_name || "").toLowerCase(),
    discoveredBy: (f) => String(f.discovered_by || "").toLowerCase(),
    status: (f) => statusRank(f.status),
    createdAt: (f) => listPagination.toTimestamp(f.created_at),
  };
  const SORT_DESC_FIRST = ["severity", "createdAt"];

  function severityAbbrev(value) {
    const key = normalizeSeverity(value, "");
    return SEVERITY_ABBREV[key] || String(value || "").toUpperCase();
  }

  function severityLabel(value) {
    const key = normalizeSeverity(value, "");
    return SEVERITY_LABELS[key] || value || "";
  }

  function humanize(value) {
    return String(value || "")
      .replace(/_/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());
  }

  function normalizeStatus(value) {
    const key = String(value || "open")
      .toLowerCase()
      .trim()
      .replace(/\s+/g, "_");
    return STATUS_ORDER.includes(key) ? key : "open";
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

  function orNull(value) {
    const text = String(value ?? "").trim();
    return text ? text : null;
  }

  function discoveredByForApi(value) {
    const text = String(value ?? "").trim();
    return text || DEFAULT_DISCOVERED_BY;
  }

  function fromApiFindingRow(raw) {
    return {
      id: raw.instance_id,
      title: raw.title,
      severity: normalizeSeverity(raw.severity),
      status: raw.status,
      created_at: raw.created_at || null,
      asset_id: raw.asset_id ?? null,
      asset_name: raw.asset_name,
      category: raw.category || "General",
      discovered_by: raw.discovered_by || DEFAULT_DISCOVERED_BY,
      definition_id: raw.definition_id ?? null,
      detailed: false,
    };
  }

  function fromApiFindingStats(raw) {
    const bySeverity = raw?.by_severity || {};
    const byStatus = raw?.by_status || {};
    const severity = {
      critical: bySeverity.critical || 0,
      high: bySeverity.high || 0,
      medium: bySeverity.medium || 0,
      low: bySeverity.low || 0,
      info: bySeverity.info || 0,
    };
    return {
      severity,
      status: { ...byStatus },
      total: Object.values(severity).reduce((sum, count) => sum + count, 0),
    };
  }

  function fromApiFindingDetail(raw) {
    const definition = raw.definition || {};
    const asset = raw.asset || {};
    return {
      id: raw.id,
      title: definition.title,
      severity: normalizeSeverity(definition.severity),
      status: raw.status,
      created_at: raw.created_at || null,
      asset_name: asset.name,
      asset_id: asset.id ?? null,
      asset_type: asset.type || "",
      definition_id: definition.id ?? null,
      category: definition.category || "General",
      description: definition.description || "",
      recommendation: definition.recommendation || "",
      tags: Array.isArray(definition.tags) ? definition.tags : [],
      evidence: raw.evidence ?? null,
      discovered_by: raw.discovered_by || DEFAULT_DISCOVERED_BY,
      notes: raw.notes || "",
      detailed: true,
      backendRecord: raw,
    };
  }

  function evidenceBlocks(evidence) {
    const asText = (value) =>
      typeof value === "string" ? value : JSON.stringify(value, null, 2);
    if (typeof evidence === "string") {
      return evidence.trim()
        ? [{ type: "general", label: "", content: evidence }]
        : [];
    }
    if (Array.isArray(evidence)) {
      return evidence
        .filter((item) => item && typeof item === "object")
        .map((item) => ({
          type: String(item.type || "general").toLowerCase(),
          label: String(item.label || item.key || ""),
          content:
            item.content == null
              ? asText(item.evidence ?? "")
              : asText(item.content),
        }))
        .filter((block) => block.content.trim().length > 0);
    }
    if (!evidence || typeof evidence !== "object") return [];
    if (Array.isArray(evidence.packages)) {
      return evidence.packages.flatMap((pkg) => {
        const type = String(pkg?.type || "general").toLowerCase();
        const items = Array.isArray(pkg?.items) ? pkg.items : [];
        return items
          .filter((item) => item && typeof item === "object")
          .map((item) => ({
            type,
            label: String(item.label || ""),
            content: item.content == null ? "" : asText(item.content),
          }))
          .filter((block) => block.content.trim().length > 0);
      });
    }
    if (Array.isArray(evidence.items)) {
      return evidence.items
        .filter((item) => item && typeof item === "object")
        .map((item) => ({
          type: String(item.type || "general").toLowerCase(),
          label: String(item.label || ""),
          content: item.content == null ? "" : asText(item.content),
        }))
        .filter((block) => block.content.trim().length > 0);
    }
    return [];
  }

  const EVIDENCE_TYPES = [
    { id: "http", label: "HTTP" },
    { id: "general", label: "General" },
  ];
  const EVIDENCE_FIELDSETS = {
    http: [
      {
        key: "Request",
        placeholder: "GET /path HTTP/1.1\nHost: example.com\n…",
        rows: 6,
      },
      {
        key: "Response",
        placeholder: "HTTP/1.1 200 OK\n…",
        rows: 6,
      },
    ],
    general: [{ key: "General", placeholder: "Evidence notes", rows: 6 }],
  };
  const MAX_EVIDENCE_BLOCKS = 10;
  const MAX_EVIDENCE_BYTES = 64000;
  let nextEvidenceUid = 1;

  function normalizeEvidenceType(value) {
    const key = String(value || "general")
      .trim()
      .toLowerCase()
      .replace(/\s+/g, "_")
      .replace(/-/g, "_");
    return key === "http" ? "http" : "general";
  }

  function evidenceTypeLabel(value) {
    const id = normalizeEvidenceType(value);
    return EVIDENCE_TYPES.find((item) => item.id === id)?.label || id;
  }

  function evidenceBlockCaption(block) {
    const type = normalizeEvidenceType(block?.type);
    const typeText = evidenceTypeLabel(type).toUpperCase();
    const label = String(block?.label || "").trim();
    if (!label) return typeText;
    const labelKey = label.toLowerCase();
    if (labelKey === type || labelKey === evidenceTypeLabel(type).toLowerCase()) {
      return typeText;
    }
    return `${typeText} · ${label}`;
  }

  function evidenceTypeIcon(value) {
    return normalizeEvidenceType(value) === "http" ? "globe" : "code";
  }

  function evidenceFieldset(type) {
    const id = normalizeEvidenceType(type);
    return EVIDENCE_FIELDSETS[id] || EVIDENCE_FIELDSETS.general;
  }

  function emptyEvidencePackage(type = "general") {
    const id = normalizeEvidenceType(type);
    return {
      uid: nextEvidenceUid++,
      type: id,
      fields: evidenceFieldset(id).map((field) => ({
        key: field.key,
        content: "",
        labelEditable: Boolean(field.labelEditable),
      })),
    };
  }

  function cloneEvidencePackage(pkg) {
    return {
      uid: pkg?.uid ?? nextEvidenceUid++,
      type: normalizeEvidenceType(pkg?.type),
      fields: (pkg?.fields || []).map((field) => ({
        key: String(field.key || ""),
        content: String(field.content || ""),
        labelEditable: Boolean(field.labelEditable),
      })),
    };
  }

  function evidencePackageSummary(pkg) {
    const keys = (pkg?.fields || [])
      .map((field) => String(field.key || "").trim())
      .filter(Boolean);
    if (keys.length) return keys.join(" / ");
    const filled = (pkg?.fields || []).some((field) =>
      String(field.content || "").trim()
    );
    return filled ? "Attached" : "Empty";
  }

  function isEvidencePackageBlank(pkg) {
    return !(pkg?.fields || []).some((field) =>
      String(field.content || "").trim()
    );
  }

  function evidencePackageItemCount(pkg) {
    return Array.isArray(pkg?.fields) ? pkg.fields.length : 0;
  }

  function evidencePackagesItemCount(packages) {
    return (packages || []).reduce(
      (sum, pkg) => sum + evidencePackageItemCount(pkg),
      0
    );
  }

  function canAddEvidencePackage(packages, type) {
    const needed = evidenceFieldset(type).length;
    return evidencePackagesItemCount(packages) + needed <= MAX_EVIDENCE_BLOCKS;
  }

  function flattenEvidencePackages(packages) {
    return (packages || []).flatMap((pkg) => {
      const type = normalizeEvidenceType(pkg.type);
      return (pkg.fields || []).map((field) => ({
        type,
        label: String(field.key || "").trim(),
        content: String(field.content || ""),
      }));
    });
  }

  function serializeEvidence(blocks) {
    const flat = (blocks || [])
      .map((block) => ({
        type: normalizeEvidenceType(block.type),
        label: String(block.label || "").trim(),
        content: String(block.content || "").replace(/\s+$/, ""),
      }))
      .filter((item) => item.content.trim().length > 0);

    const packages = [];
    let index = 0;
    while (index < flat.length) {
      const type = flat[index].type;
      const chunkSize = Math.max(1, evidenceFieldset(type).length);
      const chunk = [];
      while (
        index < flat.length &&
        flat[index].type === type &&
        chunk.length < chunkSize
      ) {
        chunk.push(flat[index]);
        index += 1;
      }
      packages.push({
        type,
        items: chunk.map((item) => ({
          label: item.label,
          content: item.content,
        })),
      });
    }
    return packages.length ? { packages } : null;
  }

  function evidenceByteSize(evidence) {
    if (evidence == null) return 0;
    return JSON.stringify(evidence).replace(/[\u0080-\uffff]/g, "\\uXXXX")
      .length;
  }

  function draftEvidencePackages(evidence) {
    const blocks = evidenceBlocks(evidence);
    if (!blocks.length) return [];
    const packages = [];
    let i = 0;
    while (i < blocks.length) {
      const type = normalizeEvidenceType(blocks[i].type);
      const fieldset = evidenceFieldset(type);
      const chunkSize = Math.max(1, fieldset.length);
      const chunk = [];
      while (
        i < blocks.length &&
        normalizeEvidenceType(blocks[i].type) === type &&
        chunk.length < chunkSize
      ) {
        chunk.push(blocks[i]);
        i += 1;
      }
      const fields = fieldset.map((field, fieldIndex) => ({
        key: field.key,
        content: String(chunk[fieldIndex]?.content || ""),
        labelEditable: Boolean(field.labelEditable),
      }));
      // If more blocks than fieldset slots (e.g. labeled general), keep extras
      if (chunk.length > fields.length) {
        for (let j = fields.length; j < chunk.length; j += 1) {
          fields.push({
            key: String(chunk[j].label || ""),
            content: String(chunk[j].content || ""),
            labelEditable: true,
          });
        }
      } else {
        chunk.forEach((block, index) => {
          if (index < fields.length && !fields[index].content) {
            fields[index].content = String(block.content || "");
            if (!fields[index].key && block.label) {
              fields[index].key = String(block.label);
            }
          }
        });
      }
      packages.push({
        uid: nextEvidenceUid++,
        type,
        fields,
      });
    }
    return packages;
  }

  function evidencePayloadFromForm(form) {
    return serializeEvidence(flattenEvidencePackages(form.evidencePackages));
  }

  function formatRawRecord(item) {
    if (!item) return "";
    try {
      return JSON.stringify(item.backendRecord || item, null, 2);
    } catch {
      return "";
    }
  }

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
    return String(text || "").trim().length > 480;
  }

  function emptyForm() {
    return {
      definition_id: null,
      title: "",
      severity: "",
      status: "open",
      category: "",
      description: "",
      recommendation: "",
      tagsText: "",
      evidencePackages: [],
      discovered_by: "",
      notes: "",
      asset_name: "",
    };
  }

  function emptyTemplateForm() {
    return {
      title: "",
      severity: "",
      category: "",
      description: "",
      recommendation: "",
      tagsText: "",
    };
  }

  function templateFormToBody(form) {
    return {
      title: String(form.title || "").trim(),
      severity: form.severity,
      category: String(form.category || "").trim() || "General",
      description: String(form.description || "").trim(),
      recommendation: String(form.recommendation || "").trim(),
      tags: tagsFromText(form.tagsText),
    };
  }

  function tagsFromText(text) {
    return String(text || "")
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean)
      .slice(0, 10);
  }

  function toCreateBody(form) {
    const body = {
      asset_name: String(form.asset_name || "").trim(),
      status: "open",
      evidence: evidencePayloadFromForm(form),
      discovered_by: discoveredByForApi(form.discovered_by),
      notes: orNull(form.notes),
    };
    if (form.definition_id != null) {
      body.definition_id = form.definition_id;
      return body;
    }
    body.title = String(form.title || "").trim();
    body.severity = normalizeSeverity(form.severity, "medium");
    body.category = orNull(form.category);
    body.description = orNull(form.description);
    body.recommendation = orNull(form.recommendation);
    body.tags = tagsFromText(form.tagsText);
    return body;
  }

  function toUpdateBody(form) {
    return {
      status: normalizeStatus(form.status),
      evidence: evidencePayloadFromForm(form),
      discovered_by: discoveredByForApi(form.discovered_by),
      notes: orNull(form.notes),
    };
  }

  function detailToForm(item) {
    return {
      definition_id: item.definition_id ?? null,
      title: item.title || "",
      severity: item.severity || "medium",
      status: item.status || "open",
      category: item.category || "",
      description: item.description || "",
      recommendation: item.recommendation || "",
      tagsText: Array.isArray(item.tags) ? item.tags.join(", ") : "",
      evidencePackages: draftEvidencePackages(item.evidence),
      discovered_by:
        item.discovered_by === DEFAULT_DISCOVERED_BY
          ? ""
          : item.discovered_by || "",
      notes: item.notes || "",
      asset_name: item.asset_name || "",
    };
  }

  function applyDefinition(form, definition, { includeTitle = true } = {}) {
    if (!definition) return form;
    return {
      ...form,
      definition_id: definition.id ?? null,
      title: includeTitle ? definition.title || form.title : form.title,
      severity: normalizeSeverity(definition.severity, "medium"),
      category: definition.category || "",
      description: definition.description || "",
      recommendation: definition.recommendation || "",
      tagsText: Array.isArray(definition.tags) ? definition.tags.join(", ") : "",
    };
  }

  /**
   * Expand GET /findings/export groups ({ id, title, assets: [...] }) into flat
   * import rows. Uses title+severity (not export id) so cross-DB / tools work.
   */
  function flattenImportRows(rawList) {
    const rows = [];
    for (let i = 0; i < rawList.length; i += 1) {
      const raw = rawList[i];
      if (
        raw &&
        typeof raw === "object" &&
        !Array.isArray(raw) &&
        Array.isArray(raw.assets) &&
        raw.assets.length
      ) {
        for (const asset of raw.assets) {
          rows.push({
            title: raw.title || raw.name,
            severity: raw.severity,
            category: raw.category,
            description: raw.description,
            recommendation: raw.recommendation || raw.remediation,
            tags: raw.tags,
            asset_name:
              asset?.asset_name || asset?.name || asset?.asset || "",
            status: asset?.status,
            evidence: asset?.evidence ?? null,
            discovered_by: asset?.discovered_by || asset?.discoveredBy,
            notes: asset?.notes || asset?.internalNotes,
          });
        }
        continue;
      }
      rows.push(raw);
    }
    return rows;
  }

  function normalizeImportEntry(raw, index) {
    const row = `Row ${index + 1}`;
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      return { error: `${row}: expected an object` };
    }
    const asset_name = String(
      raw.asset_name || raw.targetAsset || raw.target || raw.asset || ""
    ).trim();
    if (!asset_name) return { error: `${row}: missing asset_name` };

    const definition_id = Number(raw.definition_id ?? raw.definitionId);
    const hasDefinitionId =
      Number.isInteger(definition_id) && definition_id >= 1;

    const base = {
      asset_name,
      status: normalizeStatus(raw.status),
      evidence: raw.evidence ?? null,
      discovered_by: discoveredByForApi(raw.discovered_by || raw.discoveredBy),
      notes: orNull(raw.notes || raw.internalNotes),
    };

    if (hasDefinitionId) {
      return { item: { ...base, definition_id } };
    }

    const title = String(raw.title || raw.name || "").trim();
    if (!title) {
      return { error: `${row}: provide definition_id or title` };
    }
    return {
      item: {
        ...base,
        title,
        severity: normalizeSeverity(raw.severity, "medium"),
        category: orNull(raw.category),
        description: orNull(raw.description),
        recommendation: orNull(raw.recommendation || raw.remediation),
        tags: Array.isArray(raw.tags) ? raw.tags : tagsFromText(raw.tags),
      },
    };
  }

  function normalizeTitleKey(title) {
    return String(title || "").trim().toLowerCase();
  }

  function findTemplateByTitle(templates, title) {
    const key = normalizeTitleKey(title);
    if (!key) return null;
    return (
      (templates || []).find(
        (item) => normalizeTitleKey(item.title) === key
      ) || null
    );
  }

  Alpine.data("findingsPage", () => {
    const cached = pageCache.read("findings");
    const hydrated = Boolean(cached?.loaded);
    return {
    items: hydrated ? cached.items || [] : [],
    total: hydrated ? Number(cached.total) || 0 : 0,
    stats: hydrated ? cached.stats || null : null,
    assets: [],
    templates: [],
    query: "",
    /** Exact scope from Assets → View findings (`?asset=` / `?target=`). */
    assetIdFilter: null,
    assetNameFilter: null,
    filters: { severity: "all", status: "all" },
    currentPage: 1,
    pageSize: listPagination.PAGE_SIZE,
    sortKey: "severity",
    sortDir: "desc",
    entityLabel: "findings",
    loading: !hydrated,
    saving: false,
    detailLoading: false,
    error: "",
    detailError: "",
    selected: null,
    mode: "list", // list | detail | create | edit
    wizardStep: "setup", // setup | compose
    draftOrigin: "scratch", // scratch | template
    form: emptyForm(),
    templateCreateOpen: false,
    templateSaving: false,
    templateForm: emptyTemplateForm(),
    templateSeverityPreview: "",
    createdTemplate: null,
    assetQuery: "",
    assetError: "",
    templateQuery: "",
    severityPreview: "",
    descriptionExpanded: false,
    remediationExpanded: false,
    notesExpanded: false,
    evidencePage: 1,
    pickingEvidenceType: false,
    evidenceEditor: null,
    relinkOpen: false,
    relinkQuery: "",
    relinking: false,
    rawCopied: false,
    _rawCopyTimer: null,
    assetCopied: false,
    _assetCopyTimer: null,
    statusOptions: STATUS_ORDER,
    evidenceTypes: EVIDENCE_TYPES,
    severityAbbrev,
    severityLabel,
    humanize,
    formatDate,
    formatDateTime,
    proseParagraphs,
    proseCollapsible,
    normalizeSeverity,
    evidenceTypeLabel,
    evidenceBlockCaption,
    evidenceTypeIcon,
    evidencePackageSummary,
    canAddEvidencePackage,
    evidencePackagesItemCount,
    MAX_EVIDENCE_BLOCKS,

    get severityOptions() {
      const selected = this.form.severity;
      return SEVERITIES.map((id) => ({
        id,
        selected: id === selected,
        label: severityLabel(id),
        abbrev: severityAbbrev(id),
      }));
    },

    get severityDescription() {
      const id = this.severityPreview || this.form.severity;
      return SEVERITY_DESC[id] || "";
    },

    get presentSeverities() {
      const present = new Set(
        this.items.map((item) => normalizeSeverity(item.severity, ""))
      );
      return SEVERITIES.filter((level) => present.has(level));
    },

    get presentStatuses() {
      return FINDING_STATUSES.filter(
        (status) =>
          this.items.some((item) => item.status === status)
      );
    },

    get severityCounts() {
      if (this.stats?.severity) return this.stats.severity;
      const counts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      };
      for (const item of this.items) {
        const key = normalizeSeverity(item.severity, "");
        if (key in counts) counts[key] += 1;
      }
      return counts;
    },

    get severityBands() {
      const counts = this.severityCounts;
      return SEVERITIES.map((key) => ({
        key,
        shortLabel: severityAbbrev(key),
        count: Number(counts[key]) || 0,
      }));
    },

    get visibleSeverityBands() {
      return this.severityBands.filter((band) => band.count > 0);
    },

    get activeSeverityFilter() {
      return this.filters.severity === "all" ? "" : this.filters.severity;
    },

    get filtersActive() {
      return (
        this.filters.severity !== "all" ||
        this.filters.status !== "all" ||
        this.assetIdFilter != null ||
        Boolean(this.assetNameFilter)
      );
    },

    get filteredItems() {
      return this.items.filter((item) => {
        // Assets → View findings: exact id (preferred) or exact name — never substring.
        if (this.assetIdFilter != null && item.asset_id != null) {
          if (Number(item.asset_id) !== Number(this.assetIdFilter)) {
            return false;
          }
        } else if (this.assetNameFilter) {
          const name = String(item.asset_name || "")
            .trim()
            .toLowerCase();
          if (name !== this.assetNameFilter) return false;
        }
        if (
          this.filters.severity !== "all" &&
          normalizeSeverity(item.severity) !== this.filters.severity
        ) {
          return false;
        }
        if (
          this.filters.status !== "all" &&
          item.status !== this.filters.status
        ) {
          return false;
        }
        const q = this.query.trim().toLowerCase();
        if (!q) return true;
        const hay = [
          item.title,
          item.category,
          item.asset_name,
          item.discovered_by,
          item.status,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return hay.includes(q);
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

    get filteredTemplates() {
      const q = this.templateQuery.trim().toLowerCase();
      return this.templates
        .filter((item) => {
          if (!q) return true;
          return (
            String(item.title || "").toLowerCase().includes(q) ||
            String(item.category || "").toLowerCase().includes(q) ||
            (item.tags || []).some((tag) =>
              String(tag).toLowerCase().includes(q)
            )
          );
        })
        .slice()
        .sort(
          (a, b) =>
            SEVERITIES.indexOf(normalizeSeverity(a.severity)) -
            SEVERITIES.indexOf(normalizeSeverity(b.severity))
        );
    },

    get filteredRelinkTemplates() {
      const q = this.relinkQuery.trim().toLowerCase();
      return this.templates
        .filter((item) => {
          if (!q) return true;
          return (
            String(item.title || "").toLowerCase().includes(q) ||
            String(item.category || "").toLowerCase().includes(q) ||
            (item.tags || []).some((tag) =>
              String(tag).toLowerCase().includes(q)
            )
          );
        })
        .slice()
        .sort((a, b) => {
          const aCurrent = this.isRelinkCurrent(a) ? 0 : 1;
          const bCurrent = this.isRelinkCurrent(b) ? 0 : 1;
          if (aCurrent !== bCurrent) return aCurrent - bCurrent;
          return (
            SEVERITIES.indexOf(normalizeSeverity(a.severity)) -
            SEVERITIES.indexOf(normalizeSeverity(b.severity))
          );
        });
    },

    get titleLocked() {
      return this.mode === "edit" || this.draftOrigin === "template";
    },

    get templateContentLocked() {
      return this.titleLocked;
    },

    get composeNote() {
      if (this.mode === "edit") return "Template text is managed in Templates.";
      if (this.titleLocked) return "Edit title, severity, and guidance in Templates.";
      return "";
    },

    get draftSourceLabel() {
      if (this.draftOrigin === "scratch") return "New template";
      return "From template · locked";
    },

    get canSubmitCompose() {
      const title = this.form.title.trim();
      if (!title || title.length > 80) return false;
      if (this.mode === "create" && !this.form.asset_name) return false;
      if (this.mode === "create" && !this.form.severity) return false;
      if (String(this.form.notes || "").length > 2000) return false;
      if (String(this.form.discovered_by || "").length > 24) return false;
      const evidence = evidencePayloadFromForm(this.form);
      if (evidenceByteSize(evidence) > MAX_EVIDENCE_BYTES) return false;
      return true;
    },

    get templateSeverityOptions() {
      const selected = this.templateForm.severity;
      return SEVERITIES.map((id) => ({
        id,
        selected: id === selected,
        label: severityLabel(id),
        abbrev: severityAbbrev(id),
      }));
    },

    get templateSeverityDescription() {
      const id = this.templateSeverityPreview || this.templateForm.severity;
      return SEVERITY_DESC[id] || "";
    },

    get canSubmitTemplate() {
      return (
        Boolean(this.templateForm.severity) &&
        this.templateForm.title.trim().length > 0 &&
        this.templateForm.description.trim().length > 0 &&
        this.templateForm.recommendation.trim().length > 0
      );
    },

    get templateCategories() {
      const set = new Set();
      for (const item of this.templates) {
        if (item?.category) set.add(item.category);
      }
      return [...set].sort((a, b) => a.localeCompare(b));
    },

    get evidenceEditorSplit() {
      const draft = this.evidenceEditor?.draft;
      return Boolean(
        draft && draft.type === "http" && draft.fields.length === 2
      );
    },

    get evidenceEditorCanSave() {
      const draft = this.evidenceEditor?.draft;
      if (!draft || isEvidencePackageBlank(draft)) return false;
      const payload = serializeEvidence(flattenEvidencePackages([draft]));
      return evidenceByteSize(payload) <= MAX_EVIDENCE_BYTES;
    },

    get evidenceList() {
      return evidenceBlocks(this.selected?.evidence);
    },

    get activeEvidence() {
      const list = this.evidenceList;
      if (!list.length) return null;
      const index = Math.min(
        Math.max(this.evidencePage, 1),
        list.length
      );
      return list[index - 1];
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

    get isManualSource() {
      return this.isManualSourceOf(this.selected?.discovered_by);
    },

    isManualSourceOf(value) {
      return /manual|unassigned/i.test(value || "");
    },

    statusClass(status) {
      return "status-" + String(status || "").replaceAll("_", "-");
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

    async copyAsset() {
      const value = String(this.selected?.asset_name || "").trim();
      if (!value) return;
      try {
        await navigator.clipboard.writeText(value);
        this.assetCopied = true;
        clearTimeout(this._assetCopyTimer);
        this._assetCopyTimer = setTimeout(() => {
          this.assetCopied = false;
        }, 2000);
      } catch {
        this.assetCopied = false;
        toast.show("Could not copy asset", { tone: "danger" });
      }
    },

    setFilter(key, value) {
      this.filters = { ...this.filters, [key]: value || "all" };
      this.currentPage = 1;
    },

    toggleSeverityFromLegend(level) {
      const next = this.filters.severity === level ? "all" : level;
      this.setFilter("severity", next);
    },

    clearFilters() {
      this.filters = { severity: "all", status: "all" };
      this.query = "";
      this.assetIdFilter = null;
      this.assetNameFilter = null;
      this.currentPage = 1;
    },

    clearTemplateFilter() {
      this.templateQuery = "";
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

    applyAssetSearchFromRoute() {
      const params = new URLSearchParams(location.search);
      const target = String(params.get("target") || "").trim();
      const assetRaw = String(params.get("asset") || "").trim();
      const assetId = assetRaw ? Number(assetRaw) : NaN;
      const hasAssetId = Number.isFinite(assetId) && assetId > 0;
      if (!hasAssetId && !target) return;
      // Exact scope only — never dump the name into substring search alone
      // ("api.example" is contained in "mobile-api.example").
      if (hasAssetId) this.assetIdFilter = assetId;
      if (target) {
        this.assetNameFilter = target.toLowerCase();
        this.query = target;
      }
      this.currentPage = 1;
      params.delete("asset");
      params.delete("target");
      const qs = params.toString();
      history.replaceState({}, "", location.pathname + (qs ? `?${qs}` : ""));
    },

    selectSeverity(sev) {
      this.form = { ...this.form, severity: sev };
      this.severityPreview = sev;
    },

    selectTemplateSeverity(sev) {
      this.templateForm = { ...this.templateForm, severity: sev };
      this.templateSeverityPreview = sev;
    },

    evidencePrev() {
      this.evidencePage = Math.max(1, this.evidencePage - 1);
    },

    evidenceNext() {
      this.evidencePage = Math.min(
        this.evidenceList.length,
        this.evidencePage + 1
      );
    },

    evidencePlaceholder(type, fieldIndex) {
      return evidenceFieldset(type)[fieldIndex]?.placeholder || "";
    },

    evidenceFieldRows(type, fieldIndex) {
      return evidenceFieldset(type)[fieldIndex]?.rows || 8;
    },

    startEvidencePackage(type) {
      if (!canAddEvidencePackage(this.form.evidencePackages, type)) return;
      this.pickingEvidenceType = false;
      this.evidenceEditor = {
        index: null,
        isNew: true,
        draft: emptyEvidencePackage(type),
      };
    },

    openEvidenceEditor(index) {
      const pkg = this.form.evidencePackages[index];
      if (!pkg) return;
      this.evidenceEditor = {
        index,
        isNew: false,
        draft: cloneEvidencePackage(pkg),
      };
    },

    closeEvidenceEditor() {
      this.evidenceEditor = null;
    },

    saveEvidenceEditor() {
      if (!this.evidenceEditorCanSave || !this.evidenceEditor) return;
      const pkg = cloneEvidencePackage(this.evidenceEditor.draft);
      const packages = [...this.form.evidencePackages];
      if (this.evidenceEditor.isNew || this.evidenceEditor.index == null) {
        packages.push(pkg);
      } else {
        packages[this.evidenceEditor.index] = {
          ...packages[this.evidenceEditor.index],
          type: pkg.type,
          fields: pkg.fields,
        };
      }
      this.form = { ...this.form, evidencePackages: packages };
      this.evidenceEditor = null;
    },

    removeEvidencePackage(index) {
      const packages = this.form.evidencePackages.filter((_, i) => i !== index);
      this.form = { ...this.form, evidencePackages: packages };
      if (!packages.length) this.pickingEvidenceType = false;
    },

    showEvidenceTypePicker() {
      this.pickingEvidenceType = true;
    },

    hideEvidenceTypePicker() {
      this.pickingEvidenceType = false;
    },

    async init() {
      this.applyAssetSearchFromRoute();
      this.$watch("query", (value) => {
        this.currentPage = 1;
        // Emptying search also drops Assets → View findings scope.
        if (!String(value || "").trim()) {
          this.assetIdFilter = null;
          this.assetNameFilter = null;
        }
      });
      this.$watch("filteredCount", () => {
        if (this.currentPage > this.totalPages) {
          this.currentPage = this.totalPages;
        }
      });
      await Promise.all([
        this.load(),
        this.loadAssets(),
        this.loadTemplates(),
      ]);
    },

    async loadStats() {
      try {
        const raw = await api.get("/findings/stats", {
          defaultErrorMessage: "Could not load finding stats",
        });
        this.stats = fromApiFindingStats(raw);
        const cached = pageCache.read("findings") || {};
        pageCache.write("findings", {
          ...cached,
          loaded: true,
          stats: this.stats,
        });
      } catch {
        /* counts fall back to client-side tally from items */
      }
    },

    async load({ quiet } = {}) {
      // Skip Loading… panel when we already painted (cache or prior fetch).
      if (!(quiet ?? !this.loading)) this.loading = true;
      this.error = "";
      try {
        const findings = [];
        for (let skip = 0; ; skip += LIST_LIMIT) {
          const data = await api.get("/findings", {
            query: { skip, limit: LIST_LIMIT },
            defaultErrorMessage: "Could not load findings",
          });
          const page = Array.isArray(data?.findings) ? data.findings : [];
          findings.push(...page.map(fromApiFindingRow));
          const total = Number(data?.total);
          if (
            page.length < LIST_LIMIT ||
            (Number.isFinite(total) && findings.length >= total)
          ) {
            this.total = Number.isFinite(total) ? total : findings.length;
            break;
          }
        }
        this.items = findings;
        await this.loadStats();
        pageCache.write("findings", {
          loaded: true,
          items: this.items,
          total: this.total,
          stats: this.stats,
        });
      } catch (err) {
        if (api.isAbortError(err)) return;
        this.error = err.message || "Could not load findings";
        this.items = [];
        this.total = 0;
      } finally {
        this.loading = false;
      }
    },

    async loadAssets() {
      try {
        const assets = [];
        for (let skip = 0; ; skip += 500) {
          const data = await api.get("/assets", {
            query: { skip, limit: 500 },
            defaultErrorMessage: "Could not load assets",
          });
          const page = Array.isArray(data?.assets) ? data.assets : [];
          assets.push(...page);
          const total = Number(data?.total);
          if (
            page.length < 500 ||
            (Number.isFinite(total) && assets.length >= total)
          ) {
            break;
          }
        }
        this.assets = assets;
      } catch {
        this.assets = [];
      }
    },

    async loadTemplates() {
      try {
        const data = await api.get("/templates", {
          query: { skip: 0, limit: 500 },
          defaultErrorMessage: "Could not load templates",
        });
        this.templates = Array.isArray(data?.templates) ? data.templates : [];
      } catch {
        this.templates = [];
      }
    },

    toggleSelect(item) {
      this.selected = this.selected?.id === item.id ? null : item;
    },

    async openDetail(item) {
      if (!item) return;
      this.selected = item;
      this.mode = "detail";
      this.detailError = "";
      this.descriptionExpanded = false;
      this.remediationExpanded = false;
      this.notesExpanded = false;
      this.evidencePage = 1;
      this.rawCopied = false;
      clearTimeout(this._rawCopyTimer);
      this.detailLoading = true;
      try {
        const raw = await api.get(`/findings/${item.id}`, {
          defaultErrorMessage: "Could not load finding",
        });
        const detail = fromApiFindingDetail(raw);
        this.selected = detail;
        const index = this.items.findIndex((row) => row.id === detail.id);
        if (index >= 0) {
          this.items.splice(index, 1, {
            ...this.items[index],
            ...detail,
            detailed: false,
          });
        }
      } catch (err) {
        if (api.isAbortError(err)) return;
        this.detailError = err.message || "Could not load finding";
      } finally {
        this.detailLoading = false;
      }
    },

    closePanel() {
      if (this.relinking || this.templateSaving) return;
      if (this.templateCreateOpen) {
        this.closeNewTemplate({ discard: true });
        return;
      }
      if (this.mode === "detail") {
        this.mode = "list";
        this.detailError = "";
        this.relinkOpen = false;
        this.relinkQuery = "";
        this.evidenceEditor = null;
        return;
      }
      this.selected = null;
      this.mode = "list";
      this.wizardStep = "setup";
      this.draftOrigin = "scratch";
      this.form = emptyForm();
      this.detailError = "";
      this.assetQuery = "";
      this.assetError = "";
      this.templateQuery = "";
      this.severityPreview = "";
      this.pickingEvidenceType = false;
      this.evidenceEditor = null;
      this.relinkOpen = false;
      this.relinkQuery = "";
      this.templateCreateOpen = false;
      this.templateForm = emptyTemplateForm();
      this.templateSeverityPreview = "";
      this.createdTemplate = null;
      this.rawCopied = false;
      clearTimeout(this._rawCopyTimer);
    },

    startCreate() {
      this.selected = null;
      this.form = emptyForm();
      this.assetQuery = "";
      this.assetError = "";
      this.templateQuery = "";
      this.wizardStep = "setup";
      this.draftOrigin = "scratch";
      this.mode = "create";
    },

    startEdit() {
      if (!this.selected?.detailed) return;
      this.form = detailToForm(this.selected);
      this.pickingEvidenceType = false;
      this.evidenceEditor = null;
      this.wizardStep = "compose";
      this.draftOrigin = "template";
      this.mode = "edit";
    },

    resolveAsset() {
      const query = this.assetQuery.trim();
      if (!query) {
        this.assetError = "Enter a target asset.";
        return null;
      }
      const key = query.toLowerCase();
      const asset = this.assets.find(
        (item) => String(item.name || "").trim().toLowerCase() === key
      );
      if (!asset) {
        this.assetError = `No asset matches “${query}”.`;
        return null;
      }
      this.assetError = "";
      this.form = { ...this.form, asset_name: asset.name };
      return asset;
    },

    startFromTemplate(definition) {
      if (!this.resolveAsset()) return;
      this.draftOrigin = "template";
      this.form = applyDefinition(
        {
          ...emptyForm(),
          asset_name: this.form.asset_name,
          evidencePackages: [],
          discovered_by: "",
          notes: "",
        },
        definition
      );
      this.pickingEvidenceType = false;
      this.evidenceEditor = null;
      this.wizardStep = "compose";
    },

    openNewTemplate() {
      this.createdTemplate = null;
      this.templateForm = emptyTemplateForm();
      this.templateSeverityPreview = "";
      this.templateCreateOpen = true;
    },

    closeNewTemplate({ discard = false } = {}) {
      if (this.templateSaving) return;
      this.templateCreateOpen = false;
      this.templateForm = emptyTemplateForm();
      this.templateSeverityPreview = "";
      const created = discard ? null : this.createdTemplate;
      this.createdTemplate = null;
      if (!created || !this.assetQuery.trim() || !this.resolveAsset()) return;
      this.startFromTemplate(created);
    },

    async confirmTemplateDuplicateTitle() {
      const match = findTemplateByTitle(
        this.templates,
        this.templateForm.title
      );
      if (!match) return true;
      const title = String(this.templateForm.title || "").trim();
      return confirmDialog.ask({
        title: "Create another template?",
        message: `“${title}” already exists as template #${match.id}. Create a second definition with the same title?`,
        confirmLabel: "Create anyway",
        tone: "default",
      });
    },

    async saveNewTemplate() {
      if (!this.canSubmitTemplate) return;
      if (!(await this.confirmTemplateDuplicateTitle())) return;
      this.templateSaving = true;
      try {
        const created = await api.post(
          "/templates/create",
          templateFormToBody(this.templateForm),
          { defaultErrorMessage: "Could not create template" }
        );
        if (!this.templates.some((item) => item.id === created.id)) {
          this.templates = [created, ...this.templates];
        }
        this.templateQuery = "";
        this.createdTemplate = created;
        toast.show(`Created template #${created.id}`);
        this.templateSaving = false;
        this.closeNewTemplate();
      } catch (err) {
        const message = err.message || "Could not create template";
        toast.show(message, { tone: "danger" });
      } finally {
        this.templateSaving = false;
      }
    },

    goBack() {
      if (this.mode === "create" && this.wizardStep === "compose") {
        this.wizardStep = "setup";
      }
    },

    openAsset() {
      if (!this.selected?.asset_id) return;
      const params = new URLSearchParams({
        open: String(this.selected.asset_id),
      });
      location.assign(`/workspace/assets?${params.toString()}`);
    },

    openTemplate() {
      if (!this.selected?.definition_id) return;
      const params = new URLSearchParams({
        open: String(this.selected.definition_id),
      });
      location.assign(`/workspace/templates?${params.toString()}`);
    },

    takenRelinkDefinitionIds() {
      const finding = this.selected;
      if (!finding) return new Set();
      const assetId = finding.asset_id;
      const assetName = String(finding.asset_name || "")
        .trim()
        .toLowerCase();
      const ids = new Set();
      for (const item of this.items) {
        if (item.id === finding.id) continue;
        const sameAsset =
          assetId != null && item.asset_id != null
            ? item.asset_id === assetId
            : String(item.asset_name || "")
                .trim()
                .toLowerCase() === assetName;
        if (sameAsset && item.definition_id != null) {
          ids.add(item.definition_id);
        }
      }
      return ids;
    },

    isRelinkCurrent(definition) {
      return (
        this.selected?.definition_id != null &&
        definition?.id === this.selected.definition_id
      );
    },

    isRelinkTaken(definition) {
      if (this.isRelinkCurrent(definition)) return false;
      return this.takenRelinkDefinitionIds().has(definition?.id);
    },

    isRelinkUnavailable(definition) {
      return this.isRelinkCurrent(definition) || this.isRelinkTaken(definition);
    },

    relinkRowTitle(definition) {
      if (this.isRelinkCurrent(definition)) {
        return "Already linked to this finding";
      }
      if (this.isRelinkTaken(definition)) {
        return "Another finding on this asset already uses this template";
      }
      return "";
    },

    relinkRowLabel(definition) {
      const sev = severityLabel(definition?.severity);
      if (this.isRelinkCurrent(definition)) {
        return `${definition.title}, ${sev} severity, current template`;
      }
      if (this.isRelinkTaken(definition)) {
        return `${definition.title}, ${sev} severity, already on this asset`;
      }
      return `Use template ${definition.title}, ${sev} severity`;
    },

    async openRelink() {
      if (!this.selected?.detailed || this.relinking) return;
      this.relinkQuery = "";
      if (!this.templates.length) {
        await this.loadTemplates();
      }
      if (!this.templates.length) {
        toast.show("Could not load templates", { tone: "danger" });
        return;
      }
      this.relinkOpen = true;
    },

    closeRelink() {
      if (this.relinking) return;
      this.relinkOpen = false;
      this.relinkQuery = "";
    },

    async requestRelink(definition) {
      if (
        !definition ||
        this.relinking ||
        this.isRelinkUnavailable(definition) ||
        !this.selected
      ) {
        return;
      }
      const finding = this.selected;
      const asset = finding.asset_name || "this asset";
      const ok = await confirmDialog.ask({
        title: "Change template?",
        message: `“${finding.title}” on ${asset} will use “${definition.title}”. Title, severity, and guidance update from the new template. Status, evidence, and notes stay.`,
        confirmLabel: "Change template",
        tone: "default",
        action: async () => {
          this.relinking = true;
          try {
            const updated = fromApiFindingDetail(
              await api.post(
                `/findings/${finding.id}/relink`,
                { definition_id: definition.id },
                { defaultErrorMessage: "Could not change template" }
              )
            );
            this.relinkOpen = false;
            this.relinkQuery = "";
            await this.load();
            this.selected = updated;
            this.mode = "detail";
            toast.show(`Template changed to “${updated.title}”`);
          } catch (err) {
            const message = err.message || "Could not change template";
            toast.show(message, { tone: "danger" });
            throw err;
          } finally {
            this.relinking = false;
          }
        },
      });
      if (!ok) return;
    },

    async saveCreate() {
      if (!this.canSubmitCompose) return;
      if (this.draftOrigin === "scratch") {
        const dup = findTemplateByTitle(this.templates, this.form.title);
        if (dup) {
          const title = String(this.form.title || "").trim();
          const ok = await confirmDialog.ask({
            title: "Create another template?",
            message: `“${title}” already exists as template #${dup.id}. Creating this finding will also add a second library definition with the same title. Continue?`,
            confirmLabel: "Create anyway",
            tone: "default",
          });
          if (!ok) return;
        }
      }
      this.saving = true;
      try {
        const created = fromApiFindingDetail(
          await api.post("/findings/create", toCreateBody(this.form), {
            defaultErrorMessage: "Could not create finding",
          })
        );
        await this.load();
        await this.loadTemplates();
        this.openDetail(created);
        toast.show(`Created finding #${created.id}`);
      } catch (err) {
        const message = err.message || "Could not create finding";
        toast.show(message, { tone: "danger" });
      } finally {
        this.saving = false;
      }
    },

    async saveEdit() {
      if (!this.selected || !this.canSubmitCompose) return;
      this.saving = true;
      try {
        const updated = fromApiFindingDetail(
          await api.patch(
            `/findings/${this.selected.id}`,
            toUpdateBody(this.form),
            { defaultErrorMessage: "Could not update finding" }
          )
        );
        await this.load();
        this.openDetail(updated);
        toast.show(`Updated finding #${updated.id}`);
      } catch (err) {
        const message = err.message || "Could not update finding";
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
        title: "Delete this finding?",
        message: `${label} will be removed from this engagement. The template stays in the library. This can’t be undone.`,
        confirmLabel: "Delete finding",
        action: async () => {
          this.saving = true;
          try {
            await api.delete(`/findings/${selected.id}`, {
              defaultErrorMessage: "Could not delete finding",
            });
            this.closePanel();
            await this.load();
            toast.show(`Deleted finding ${label}`);
          } catch (err) {
            const message = err.message || "Could not delete finding";
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
        title: "Import findings",
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
          : Array.isArray(parsed?.vulnerabilities)
            ? parsed.vulnerabilities
            : Array.isArray(parsed?.findings)
              ? parsed.findings
              : null;
        if (!rawList) {
          throw new Error("Import JSON has the wrong shape");
        }
        if (!rawList.length) throw new Error("Import file has no findings");

        const flatList = flattenImportRows(rawList);
        const entries = [];
        for (let i = 0; i < flatList.length; i += 1) {
          const result = normalizeImportEntry(flatList[i], i);
          if (result.error) throw new Error(result.error);
          entries.push(result.item);
        }
        if (entries.length > IMPORT_BATCH) {
          throw new Error(
            `Import cancelled. File has ${entries.length} findings; max is ${IMPORT_BATCH}.`
          );
        }

        // Single request: backend is all-or-nothing (no partial imports).
        const data = await api.post(
          "/findings/import",
          { vulnerabilities: entries },
          { defaultErrorMessage: "Could not import findings" }
        );
        const imported = Number(data?.summary?.imported) || 0;
        const feedback = importFeedback.formatFindingImportFeedback({ imported });
        importFeedback.presentImportFeedback(feedback);
        if (!feedback.failureMessage) {
          await this.load();
          await this.loadTemplates();
        }
        return true;
      } catch (err) {
        if (err instanceof SyntaxError) {
          toast.show("Import file is not valid JSON", { tone: "danger" });
          return false;
        }
        if (
          Number(err?.status) === 400 &&
          (/^Import cancelled/i.test(String(err?.message || "")) ||
            importFeedback.importErrorsFrom(err).length)
        ) {
          importFeedback.presentImportFeedback(
            importFeedback.formatFindingImportCancel(err)
          );
          return true;
        }
        toast.show(
          importFeedback.formatImportCatchMessage(
            err,
            "Could not import findings"
          ),
          { tone: "danger" }
        );
        return false;
      } finally {
        this.saving = false;
      }
    },

    async exportReport() {
      this.saving = true;
      try {
        const { blob, filename } = await api.getBlob("/findings/report", {
          defaultErrorMessage: "Could not export findings report",
        });
        const day = new Date().toISOString().slice(0, 10);
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = filename || `findings-report-${day}.pdf`;
        link.click();
        URL.revokeObjectURL(url);
        toast.show("Findings report exported");
      } catch (err) {
        const message = err.message || "Could not export findings report";
        toast.show(message, { tone: "danger" });
      } finally {
        this.saving = false;
      }
    },
  };
  });
});
