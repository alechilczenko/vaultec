/* Compact toast copy + import-result sections for bulk imports. */
(function (global) {
  "use strict";

  const TOAST_MAX_CHARS = 140;

  const plural = (count, singular, pluralForm = `${singular}s`) =>
    `${count} ${count === 1 ? singular : pluralForm}`;

  function clipToastMessage(message, fallback = "") {
    const text = String(message ?? "").trim() || String(fallback || "").trim();
    if (!text) return "";
    if (text.length <= TOAST_MAX_CHARS) return text;
    return `${text.slice(0, TOAST_MAX_CHARS - 1).trimEnd()}…`;
  }

  /** FastAPI/Pydantic 422 bodies (array of {loc, msg, type}). */
  function isSchemaValidationError(err) {
    if (Number(err?.status) === 422) return true;
    const detail = err?.detail;
    if (!Array.isArray(detail) || !detail.length) return false;
    const first = detail[0];
    return Boolean(
      first &&
        (typeof first.msg === "string" ||
          typeof first.type === "string" ||
          Array.isArray(first.loc))
    );
  }

  function importErrorsFrom(err) {
    const detail = err?.detail;
    if (Array.isArray(err?.errors)) return err.errors.map(String);
    if (detail && typeof detail === "object" && !Array.isArray(detail)) {
      if (Array.isArray(detail.errors)) return detail.errors.map(String);
    }
    return [];
  }

  /**
   * Toast copy for failed imports. Hides raw Pydantic 422 text.
   * Callers still special-case SyntaxError for invalid JSON files.
   */
  function formatImportCatchMessage(err, fallback = "Could not import") {
    if (isSchemaValidationError(err)) {
      return "Import JSON does not match the expected schema";
    }
    const raw = String(err?.message || "").trim();
    if (
      /^JSON must be an array/i.test(raw) ||
      /wrong shape/i.test(raw)
    ) {
      return "Import JSON has the wrong shape";
    }
    if (/^Import cancelled/i.test(raw)) {
      return clipToastMessage(raw, "Import cancelled");
    }
    return clipToastMessage(raw, fallback);
  }

  function formatLabel(item) {
    if (item == null) return "";
    if (typeof item === "string" || typeof item === "number") return String(item);
    const id = item.id != null ? `#${item.id}` : "";
    const title = String(item.title || item.name || "").trim();
    if (title && id) return `${title} (${id})`;
    return title || id || "";
  }

  function formatFindingImportFeedback({ imported = 0 } = {}) {
    if (!imported) {
      const failureMessage = "No findings were imported";
      return {
        failureMessage,
        summary: failureMessage,
        tone: "danger",
        title: "Findings import",
        sections: [],
      };
    }
    return {
      failureMessage: "",
      summary: `Imported ${plural(imported, "finding")}`,
      tone: "success",
      title: "Findings import",
      sections: [],
    };
  }

  function formatFindingImportCancel(err) {
    const errors = importErrorsFrom(err);
    return {
      failureMessage: "Import cancelled",
      summary: "Import cancelled",
      tone: "danger",
      title: "Findings import cancelled",
      sections: errors.length
        ? [{ label: plural(errors.length, "Error"), items: errors }]
        : [],
    };
  }

  function formatAssetImportFeedback({
    added = 0,
    skipped = 0,
    addedNames = [],
    skippedNames = [],
  } = {}) {
    const addedItems = (addedNames || []).map(formatLabel).filter(Boolean);
    const skippedItems = (skippedNames || []).map(formatLabel).filter(Boolean);
    const sections = [];
    if (addedItems.length) {
      sections.push({ label: `Added (${addedItems.length})`, items: addedItems });
    }
    if (skippedItems.length) {
      sections.push({
        label: `Already registered (${skippedItems.length})`,
        items: skippedItems,
      });
    }

    if (!added && skipped) {
      const failureMessage = `No new assets. ${skipped} already registered`;
      return {
        failureMessage,
        summary: failureMessage,
        tone: "danger",
        title: "Assets import",
        sections,
      };
    }
    if (!added) {
      const failureMessage = "No assets were imported";
      return {
        failureMessage,
        summary: failureMessage,
        tone: "danger",
        title: "Assets import",
        sections,
      };
    }
    if (skipped) {
      return {
        failureMessage: "",
        summary: `Imported ${plural(added, "asset")} · ${skipped} already registered`,
        tone: "warning",
        title: "Assets import",
        sections,
      };
    }
    return {
      failureMessage: "",
      summary: `Imported ${plural(added, "asset")}`,
      tone: "success",
      title: "Assets import",
      sections,
    };
  }

  function formatTemplatesImportFeedback({
    created = 0,
    updated = 0,
    createdItems = [],
    updatedItems = [],
  } = {}) {
    const createdLabels = (createdItems || []).map(formatLabel).filter(Boolean);
    const updatedLabels = (updatedItems || []).map(formatLabel).filter(Boolean);
    const sections = [];
    if (createdLabels.length) {
      sections.push({
        label: `Created (${createdLabels.length})`,
        items: createdLabels,
      });
    }
    if (updatedLabels.length) {
      sections.push({
        label: `Updated (${updatedLabels.length})`,
        items: updatedLabels,
      });
    }

    if (!created && !updated) {
      const failureMessage = "No templates imported";
      return {
        failureMessage,
        summary: failureMessage,
        tone: "danger",
        title: "Templates import",
        sections,
      };
    }
    if (!created) {
      return {
        failureMessage: "",
        summary: `Updated ${plural(updated, "template")}`,
        tone: "warning",
        title: "Templates import",
        sections,
      };
    }
    if (!updated) {
      return {
        failureMessage: "",
        summary: `Created ${plural(created, "template")}`,
        tone: "success",
        title: "Templates import",
        sections,
      };
    }
    return {
      failureMessage: "",
      summary: `Imported ${plural(created + updated, "template")} · ${created} created, ${updated} updated`,
      tone: "warning",
      title: "Templates import",
      sections,
    };
  }

  function presentImportFeedback(feedback) {
    if (!feedback) return;
    const summary = feedback.summary || feedback.failureMessage || "";
    if (summary) toast.show(summary, { tone: feedback.tone || "info" });
    if (Array.isArray(feedback.sections) && feedback.sections.some((s) => s.items?.length)) {
      importResult.show({
        title: feedback.title || "Import result",
        summary,
        tone: feedback.tone || "info",
        sections: feedback.sections,
      });
    }
  }

  global.importFeedback = {
    TOAST_MAX_CHARS,
    clipToastMessage,
    isSchemaValidationError,
    formatImportCatchMessage,
    importErrorsFrom,
    formatFindingImportFeedback,
    formatFindingImportCancel,
    formatAssetImportFeedback,
    formatTemplatesImportFeedback,
    presentImportFeedback,
  };
})(window);
