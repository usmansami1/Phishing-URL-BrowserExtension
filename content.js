/**
 * PhishGuard - Content Script
 * Monitors top-level page URL transitions (including history back/forward,
 * hash changes, and bfcache restores) and lightweight page form signals.
 */
(function () {
  'use strict';

  // Top-level frame only
  if (window !== window.top) return;

  let lastReportedUrl = '';
  let signalsSentForUrl = '';

  function isContextValid() {
    return typeof chrome !== 'undefined' && Boolean(chrome.runtime && chrome.runtime.id);
  }

  function safeSendMessage(payload) {
    if (!isContextValid()) return;
    try {
      const maybePromise = chrome.runtime.sendMessage(payload);
      if (maybePromise && typeof maybePromise.catch === 'function') {
        maybePromise.catch(function () {
          // Ignore transient service worker wake-up or closed channel errors
        });
      }
    } catch (_) {
      // Extension context may be invalidated after extension reload
    }
  }

  function reportCurrentUrl(eventType) {
    const currentUrl = window.location.href;
    if (!currentUrl || (!currentUrl.startsWith('http://') && !currentUrl.startsWith('https://'))) {
      return;
    }
    if (eventType !== 'pageshow' && currentUrl === lastReportedUrl) {
      return;
    }
    lastReportedUrl = currentUrl;
    safeSendMessage({
      type: 'PHISHGUARD_CONTENT_URL',
      url: currentUrl,
      event: eventType,
    });
  }

  function inspectLightweightPageSignals() {
    const currentUrl = window.location.href;
    if (!currentUrl || signalsSentForUrl === currentUrl) return;
    if (!currentUrl.startsWith('http://') && !currentUrl.startsWith('https://')) return;

    const hasPasswordField = Boolean(document.querySelector('input[type="password"]'));
    let hasCrossOriginForm = false;

    const currentHost = window.location.hostname.toLowerCase();
    const forms = document.querySelectorAll('form[action]');
    for (let i = 0; i < forms.length; i++) {
      const rawAction = forms[i].getAttribute('action');
      if (!rawAction || rawAction.startsWith('#') || rawAction.startsWith('/')) continue;
      try {
        const actionUrl = new URL(rawAction, currentUrl);
        if (
          (actionUrl.protocol === 'http:' || actionUrl.protocol === 'https:') &&
          actionUrl.hostname.toLowerCase() !== currentHost
        ) {
          hasCrossOriginForm = true;
          break;
        }
      } catch (_) {
        // Ignore malformed form action
      }
    }

    // Only notify background when an actionable signal is present on this page
    if ((hasPasswordField && window.location.protocol === 'http:') || hasCrossOriginForm) {
      signalsSentForUrl = currentUrl;
      safeSendMessage({
        type: 'PHISHGUARD_PAGE_SIGNALS',
        url: currentUrl,
        signals: {
          hasPasswordField,
          hasCrossOriginForm,
        },
      });
    }
  }

  // Initial URL extraction
  reportCurrentUrl('load');

  // Client-side navigation & bfcache restoration listeners
  window.addEventListener('popstate', function () {
    reportCurrentUrl('popstate');
  });

  window.addEventListener('hashchange', function () {
    reportCurrentUrl('hashchange');
  });

  window.addEventListener('pageshow', function (event) {
    if (event.persisted) {
      reportCurrentUrl('pageshow');
    }
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inspectLightweightPageSignals, { once: true });
  } else {
    inspectLightweightPageSignals();
  }
})();
