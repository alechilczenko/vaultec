/* Client-side list pagination + sort. */
(function (global) {
  "use strict";

  const PAGE_SIZE = 8;

  function totalPages(count, perPage) {
    const size = perPage || PAGE_SIZE;
    return Math.max(1, Math.ceil((Number(count) || 0) / size));
  }

  function clampPage(page, pages) {
    return Math.min(Math.max(Number(page) || 1, 1), pages || 1);
  }

  function pageSlice(items, page, perPage) {
    const list = Array.isArray(items) ? items : [];
    const size = perPage || PAGE_SIZE;
    const pages = totalPages(list.length, size);
    const current = clampPage(page, pages);
    const start = (current - 1) * size;
    return list.slice(start, start + size);
  }

  /** First, last, and neighbors of the current page; gaps → ellipsis. */
  function pageItems(current, pages) {
    if (pages <= 1) return [];
    const numbers = Array.from({ length: pages }, (_, index) => index + 1).filter(
      (page) => page === 1 || page === pages || Math.abs(page - current) <= 1
    );
    const items = [];
    numbers.forEach((page, index) => {
      if (index > 0 && page - numbers[index - 1] > 1) {
        items.push({
          type: "ellipsis",
          key: `gap-${numbers[index - 1]}-${page}`,
        });
      }
      items.push({ type: "page", value: page, key: `page-${page}` });
    });
    return items;
  }

  function rangeMeta(page, total, perPage) {
    const size = perPage || PAGE_SIZE;
    const count = Number(total) || 0;
    if (!count) return { start: 0, end: 0 };
    const current = clampPage(page, totalPages(count, size));
    return {
      start: (current - 1) * size + 1,
      end: Math.min(current * size, count),
    };
  }

  function toTimestamp(value) {
    if (value == null || value === "") return 0;
    if (typeof value === "number" && Number.isFinite(value)) return value;
    const date = value instanceof Date ? value : new Date(String(value).trim().replace(" ", "T"));
    const time = date.getTime();
    return Number.isNaN(time) ? 0 : time;
  }

  /** Sort filtered rows by active sort key / direction. */
  function sortItems(items, sortKey, sortDir, accessors) {
    const list = Array.isArray(items) ? items : [];
    const accessor = sortKey && accessors ? accessors[sortKey] : null;
    if (!accessor) return list;
    const direction = sortDir === "asc" ? 1 : -1;
    return [...list].sort((a, b) => {
      const va = accessor(a);
      const vb = accessor(b);
      if (typeof va === "number" && typeof vb === "number") {
        return (va - vb) * direction;
      }
      return (
        String(va).localeCompare(String(vb), undefined, { numeric: true }) *
        direction
      );
    });
  }

  function nextSortState(sortKey, sortDir, key, accessors, descFirst = []) {
    if (!accessors || !accessors[key]) {
      return { sortKey, sortDir };
    }
    if (sortKey === key) {
      return {
        sortKey,
        sortDir: sortDir === "asc" ? "desc" : "asc",
      };
    }
    return {
      sortKey: key,
      sortDir: descFirst.includes(key) ? "desc" : "asc",
    };
  }

  function sortIcon(sortKey, sortDir, key) {
    if (sortKey !== key) return "sort";
    return sortDir === "asc" ? "chevron-up" : "chevron-down";
  }

  function sortAria(sortKey, sortDir, key) {
    if (sortKey !== key) return null;
    return sortDir === "asc" ? "ascending" : "descending";
  }

  /** Full SVG for SortHeader — avoids `$icon(sortIcon(...))` nesting (rendered as "undefined"). */
  function sortIconHtml(sortKey, sortDir, key) {
    const name = sortIcon(sortKey, sortDir, key);
    if (typeof global.iconSvg === "function") {
      return global.iconSvg(name, 12) || "";
    }
    return "";
  }

  global.listPagination = {
    PAGE_SIZE,
    totalPages,
    clampPage,
    pageSlice,
    pageItems,
    rangeMeta,
    toTimestamp,
    sortItems,
    nextSortState,
    sortIcon,
    sortAria,
    sortIconHtml,
  };
})(window);
