(function () {
  window.htmx = window.htmx || {};
  window.htmx.config = window.htmx.config || {};
  window.htmx.config.allowEval = false;
  window.htmx.config.allowScriptTags = false;
  window.htmx.config.includeIndicatorStyles = false;
})();

function clearResults() {
  document.body.classList.add("is-loading");
}

document.addEventListener("htmx:beforeRequest", function (event) {
  if (event.detail && event.detail.elt && event.detail.elt.matches(".inspect-form")) {
    document.body.classList.add("is-loading");
  }
});

document.addEventListener("htmx:afterSwap", function () {
  document.body.classList.remove("is-loading");
});

document.addEventListener("htmx:responseError", function () {
  document.body.classList.remove("is-loading");
});

document.addEventListener("click", function (event) {
  var button = event.target.closest("[data-target-tab], [data-artifact-tab]");
  if (!button) {
    return;
  }
  event.preventDefault();
  var isArtifact = button.hasAttribute("data-artifact-tab");
  var root = button.closest(isArtifact ? "[data-artifact-tabs]" : "[data-target-tabs]");
  if (!root) {
    return;
  }
  var tabAttr = isArtifact ? "data-artifact-tab" : "data-target-tab";
  var panelSelector = isArtifact ? "[data-artifact-panel]" : "[data-target-panel]";
  var target = button.getAttribute(tabAttr);
  root.querySelectorAll(":scope > .tab-list [" + tabAttr + "]").forEach(function (tab) {
    var active = tab === button;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  root.querySelectorAll(":scope > " + panelSelector).forEach(function (panel) {
    var active = isArtifact ? panel.getAttribute("data-artifact-panel") === target : panel.id === target;
    panel.classList.toggle("is-active", active);
    panel.hidden = !active;
  });
});
