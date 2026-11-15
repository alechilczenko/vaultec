/* Alpine helper for Radix Icons. */
(function (global) {
  "use strict";

  function iconSvg(name, size) {
    const paths = global.ICON_PATHS && global.ICON_PATHS[name];
    if (!paths) return "";
    const s = size == null ? 16 : size;
    const body = paths
      .map(
        (d) =>
          `<path d="${d}" fill="currentColor" fill-rule="evenodd" clip-rule="evenodd"></path>`
      )
      .join("");
    return (
      `<svg class="app-icon" width="${s}" height="${s}" viewBox="0 0 15 15" ` +
      `fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">${body}</svg>`
    );
  }

  document.addEventListener("alpine:init", () => {
    Alpine.magic("icon", () => iconSvg);
  });

  global.iconSvg = iconSvg;
})(window);
