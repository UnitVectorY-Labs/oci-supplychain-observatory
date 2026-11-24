// Application-specific progressive enhancements for OCI Supply Chain Observatory.
// Core theme toggle, cookie persistence, copy buttons and ARIA tabs are provided by uvy.js.
(function () {
  function activateScope(id, updateHash) {
    if (!id) return;
    var panel = document.getElementById(id);
    if (!panel || !panel.matches("[data-scope-panel]")) return;

    document.querySelectorAll("[data-scope-panel]").forEach(function (item) {
      item.hidden = item !== panel;
    });
    document.querySelectorAll("[data-coverage-row]").forEach(function (row) {
      var active = row.dataset.coverageRow === id;
      row.classList.toggle("scope-row--active", active);
      var btn = row.querySelector("[data-scope-select]");
      if (btn) btn.setAttribute("aria-pressed", String(active));
    });
    document.querySelectorAll("[data-scope-dropdown]").forEach(function (select) {
      select.value = id;
    });
    if (updateHash) {
      try {
        history.replaceState(null, "", "#" + id);
      } catch (_) {}
      panel.scrollIntoView({ block: "start" });
    }
  }

  function syncScopeFromHash() {
    var hash = (location.hash || "").replace(/^#/, "");
    if (hash && document.getElementById(hash)) {
      activateScope(hash, false);
    }
  }

  // Always enhance the live document after HTMX swaps/processes/settles new nodes
  // so outerHTML swaps (whose old target is detached) never leave [data-enable-with-js]
  // buttons or tablists uninitialized.
  function refreshInteractiveState() {
    if (typeof window.uvyEnhance === "function") {
      window.uvyEnhance(document);
    }
    syncScopeFromHash();
  }

  document.addEventListener("DOMContentLoaded", refreshInteractiveState);
  document.addEventListener("htmx:after:swap", refreshInteractiveState);
  document.addEventListener("htmx:after:process", refreshInteractiveState);
  document.addEventListener("htmx:after:settle", refreshInteractiveState);
  document.addEventListener("htmx:afterSwap", refreshInteractiveState);
  document.addEventListener("htmx:afterSettle", refreshInteractiveState);
  window.addEventListener("hashchange", syncScopeFromHash);

  document.addEventListener("click", function (event) {
    var regBtn = event.target.closest("[data-registry]");
    if (regBtn) {
      var input = document.getElementById("image-reference");
      if (input) {
        input.value = regBtn.dataset.registry + "/";
        input.focus();
      }
      return;
    }

    var scopeBtn = event.target.closest("[data-scope-select]");
    if (scopeBtn) {
      activateScope(scopeBtn.dataset.scopeSelect, true);
      return;
    }

    var openTabBtn = event.target.closest("[data-open-tab]");
    if (openTabBtn) {
      var tab = document.getElementById(openTabBtn.dataset.openTab);
      if (tab) {
        tab.click();
        tab.focus({ preventScroll: true });
        var tablist = tab.closest('[role="tablist"]');
        if (tablist) {
          tablist.scrollIntoView({ block: "start", behavior: "smooth" });
        }
      }
      return;
    }

    var facetBtn = event.target.closest("[data-facet-field]");
    if (facetBtn) {
      var form = document.getElementById(facetBtn.dataset.facetForm || "");
      if (!form) return;
      var field = form.querySelector('[name="' + facetBtn.dataset.facetField + '"]');
      if (!field) return;
      var nextVal = facetBtn.dataset.facetValue || "";
      field.value = field.value === nextVal ? "" : nextVal;
      var pageInput = form.querySelector('[name="page"]');
      if (pageInput) pageInput.value = "1";
      var container = form.closest("[data-sbom-container]");
      if (container) {
        container.querySelectorAll('[data-facet-field="' + facetBtn.dataset.facetField + '"]').forEach(function (btn) {
          btn.setAttribute("aria-pressed", String(btn.dataset.facetValue === field.value && field.value !== ""));
        });
      }
      field.dispatchEvent(new Event("change", { bubbles: true }));
      return;
    }

    var clearBtn = event.target.closest("[data-clear-sbom]");
    if (clearBtn) {
      var sbomForm = document.getElementById(clearBtn.dataset.clearSbom || "");
      if (!sbomForm) return;
      sbomForm.querySelectorAll('input[type="search"], select').forEach(function (el) {
        el.value = "";
      });
      var pInput = sbomForm.querySelector('[name="page"]');
      if (pInput) pInput.value = "1";
      var sbomContainer = sbomForm.closest("[data-sbom-container]");
      if (sbomContainer) {
        sbomContainer.querySelectorAll("[data-facet-field]").forEach(function (btn) {
          btn.setAttribute("aria-pressed", "false");
        });
      }
      var searchField = sbomForm.querySelector('input[type="search"]');
      if (searchField) {
        searchField.dispatchEvent(new Event("change", { bubbles: true }));
        searchField.focus();
      }
    }
  });

  document.addEventListener("change", function (event) {
    if (event.target.matches("[data-scope-dropdown]")) {
      activateScope(event.target.value, true);
      return;
    }
    if (event.target.matches("[data-sbom-filter]")) {
      var form = event.target.closest("form");
      if (!form) return;
      var pageInput = form.querySelector('[name="page"]');
      if (pageInput) pageInput.value = "1";
      var container = form.closest("[data-sbom-container]");
      if (container && event.target.name) {
        container.querySelectorAll('[data-facet-field="' + event.target.name + '"]').forEach(function (btn) {
          btn.setAttribute("aria-pressed", String(btn.dataset.facetValue === event.target.value && event.target.value !== ""));
        });
      }
    }
  });

  // Recover cleanly if job polling hits a network or server error.
  function handlePollingError(event) {
    var polling = document.querySelector("#inspection-panel[data-polling]");
    if (!polling) return;
    var source =
      (event.detail && event.detail.ctx && event.detail.ctx.sourceElement) ||
      (event.detail && event.detail.elt) ||
      event.target;
    if (source && source !== polling && !polling.contains(source)) return;
    polling.removeAttribute("hx-trigger");
    var errEl = polling.querySelector("[data-polling-error]");
    var spinEl = polling.querySelector("[data-polling-active]");
    if (spinEl) spinEl.hidden = true;
    if (errEl) errEl.hidden = false;
  }
  document.addEventListener("htmx:response:error", handlePollingError);
  document.addEventListener("htmx:responseError", handlePollingError);
  document.addEventListener("htmx:sendError", handlePollingError);
  document.addEventListener("htmx:error", handlePollingError);
})();
