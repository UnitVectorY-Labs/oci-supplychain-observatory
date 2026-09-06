(function () {
  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    document.querySelectorAll('[data-theme-toggle]').forEach(function (button) {
      var label = theme === 'dark' ? 'Light mode' : 'Dark mode';
      button.textContent = label;
      button.setAttribute('aria-label', 'Switch to ' + label.toLowerCase());
    });
  }
  var theme = 'dark';
  try { if (localStorage.getItem('observatory-theme') === 'light') theme = 'light'; } catch (_) {}
  applyTheme(theme);

  function activateTarget(id, navigate) {
    var panel = document.getElementById(id);
    if (!panel || !panel.matches('[data-target-panel]')) return;
    document.querySelectorAll('[data-target-panel]').forEach(function (item) { item.hidden = item !== panel; });
    document.querySelectorAll('[data-coverage-row]').forEach(function (row) {
      var active = row.dataset.coverageRow === id;
      row.classList.toggle('is-selected', active);
      row.querySelector('[data-target-link]').setAttribute('aria-pressed', String(active));
    });
    var select = document.querySelector('[data-scope-select]');
    if (select) select.value = id;
    if (navigate) {
      history.replaceState(null, '', '#' + id);
      panel.scrollIntoView({block: 'start'});
      var heading = panel.querySelector('h2');
      if (heading) { heading.tabIndex = -1; heading.focus({preventScroll: true}); }
    }
  }
  function refresh() {
    applyTheme(document.documentElement.dataset.theme || 'dark');
    activateTarget(location.hash.slice(1), false);
  }
  document.addEventListener('htmx:after:swap', refresh);
  document.addEventListener('htmx:afterSwap', refresh);
  window.addEventListener('hashchange', refresh);
  refresh();

  document.addEventListener('click', async function (event) {
    var button = event.target.closest('button');
    if (!button) return;
    if (button.matches('[data-theme-toggle]')) {
      var theme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
      applyTheme(theme);
      try { localStorage.setItem('observatory-theme', theme); } catch (_) {}
    } else if (button.matches('[data-registry]')) {
      var input = document.getElementById('image-reference');
      // Registry choices are an input aid; the server remains the authority on access.
      input.value = button.dataset.registry + '/';
      input.focus();
    } else if (button.matches('[data-copy]')) {
      try { await navigator.clipboard.writeText(button.dataset.copy); button.textContent = 'Copied'; }
      catch (_) { button.textContent = 'Select the reference above to copy'; }
    } else if (button.matches('[data-target-link]')) {
      activateTarget(button.dataset.targetLink, true);
    } else if (button.matches('[data-artifact-tab]')) {
      var root = button.closest('[data-artifact-tabs]');
      root.querySelectorAll(':scope > .tab-list [data-artifact-tab]').forEach(function (tab) {
        var active = tab === button;
        tab.classList.toggle('is-active', active);
        tab.setAttribute('aria-selected', String(active));
        tab.tabIndex = active ? 0 : -1;
      });
      root.querySelectorAll(':scope > [data-artifact-panel]').forEach(function (panel) {
        panel.hidden = panel.dataset.artifactPanel !== button.dataset.artifactTab;
      });
    }
  });
  document.addEventListener('change', function (event) {
    if (event.target.matches('[data-scope-select]')) activateTarget(event.target.value, true);
  });
  document.addEventListener('input', function (event) {
    if (!event.target.matches('.component-filter')) return;
    var root = event.target.closest('.component-inventory');
    var query = event.target.value.trim().toLowerCase();
    var count = 0;
    root.querySelectorAll('tbody tr').forEach(function (row) {
      row.hidden = !row.textContent.toLowerCase().includes(query);
      if (!row.hidden) count++;
    });
    root.querySelector('.filter-count').textContent = count + ' packages shown' + (count === 0 ? ' · Try another search.' : '');
  });
  document.addEventListener('keydown', function (event) {
    if (!event.target.matches('[role="tab"]')) return;
    var tabs = Array.from(event.target.closest('[role="tablist"]').querySelectorAll('[role="tab"]'));
    var index = tabs.indexOf(event.target);
    if (event.key === 'ArrowRight') index = (index + 1) % tabs.length;
    else if (event.key === 'ArrowLeft') index = (index + tabs.length - 1) % tabs.length;
    else if (event.key === 'Home') index = 0;
    else if (event.key === 'End') index = tabs.length - 1;
    else return;
    event.preventDefault(); tabs[index].click(); tabs[index].focus();
  });
})();
