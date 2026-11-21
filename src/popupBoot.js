(function () {
  try {
    var params = new URLSearchParams(window.location.search);
    var mode = params.get('mode') || '';
    var rootEl = document.documentElement;
    if (!rootEl || !rootEl.classList) return;
    if (mode === 'popup') {
      rootEl.classList.add('pg-popup');
    }
    if (mode === 'popup' || mode === 'status' || mode === 'scanner' || mode === 'warning') {
      rootEl.classList.add('pg-hydrating');
      setTimeout(function () {
        rootEl.classList.remove('pg-hydrating');
      }, 250);
    }
  } catch (_) {
    // Ignore URL parsing issues
  }
})();
