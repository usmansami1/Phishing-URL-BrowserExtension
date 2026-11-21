/**
 * PhishGuard - Manifest V3 Background Service Worker
 * Coordinates navigation monitoring, URL extraction, caching, per-tab state,
 * badge indicators, full-screen phishing redirects, and Back-to-Safety navigation.
 */

importScripts('./src/brandDetector.js', './src/urlAnalyzer.js', './src/ruleEngine.js', './src/riskScorer.js', './src/detector.js');

'use strict';

const SESSION_STORAGE_KEY = 'phishguard_tab_states_v1';
const DETECTOR_ENGINE_VERSION = 7;
const POPUP_PAGE_PATH = 'index.html?mode=popup';
const REDIRECT_LOCK_MS = 350;

const tabStates = new Map();
const redirectLocks = new Map();
const tabNavEpochs = new Map();
let hydrationPromise = null;
let lastSourceTab = { tabId: null, url: '' };
let actionClickQueue = Promise.resolve();

function getWarningPageBaseUrl() {
  return chrome.runtime.getURL('index.html');
}

function getScannerPageBaseUrl() {
  return chrome.runtime.getURL('scanner.html');
}

function isWarningPageUrl(url) {
  if (typeof url !== 'string') return false;
  return url.startsWith(getWarningPageBaseUrl());
}

function isScannerPageUrl(url) {
  if (typeof url !== 'string') return false;
  return url.startsWith(getScannerPageBaseUrl());
}

function isExtensionUiPageUrl(url) {
  if (typeof url !== 'string') return false;
  const extRoot = chrome.runtime.getURL('');
  return (
    isWarningPageUrl(url) ||
    isScannerPageUrl(url) ||
    (Boolean(extRoot) && url.startsWith(extRoot))
  );
}

function buildExtensionUiPageMeta(titleLabel) {
  return {
    supported: false,
    exempt: true,
    valid: false,
    isInternalBrowserPage: true,
    isExtensionUiPage: true,
    uiState: 'neutral',
    extensionTitle: titleLabel || 'PhishGuard – Extension Interface',
    outcome: 'EXEMPT',
    classification: 'EXEMPT',
    riskLevel: 'Exempt',
    riskBadge: 'EXEMPT',
  };
}

function parseWarningParams(url) {
  try {
    const parsed = new URL(url);
    const targetUrl =
      parsed.searchParams.get('url') || parsed.searchParams.get('targetUrl') || '';
    const tabIdParam =
      parsed.searchParams.get('tabId') ?? parsed.searchParams.get('targetTabId');
    return {
      mode: parsed.searchParams.get('mode') || '',
      targetUrl,
      tabId: tabIdParam !== null && tabIdParam !== '' && !Number.isNaN(Number(tabIdParam))
        ? Number(tabIdParam)
        : null,
    };
  } catch (_) {
    return { mode: '', targetUrl: '', tabId: null };
  }
}

function buildStatusTabUrl(targetTabId, targetUrl) {
  const base = getWarningPageBaseUrl();
  const params = new URLSearchParams();
  params.set('mode', 'status');
  if (typeof targetTabId === 'number' && !Number.isNaN(targetTabId)) {
    params.set('targetTabId', String(targetTabId));
  }
  if (targetUrl) {
    params.set('targetUrl', targetUrl);
  }
  return `${base}?${params.toString()}`;
}

function createEmptyTabState() {
  return {
    currentUrl: '',
    lastRawUrl: '',
    lastAnalyzedUrl: '',
    lastAnalyzedAt: 0,
    lastResult: null,
    lastSafeUrl: '',
    dismissedHostnames: [],
    pendingWarning: null,
    pageSignals: null,
  };
}

async function ensureHydrated() {
  if (hydrationPromise) {
    return hydrationPromise;
  }
  hydrationPromise = (async () => {
    try {
      if (chrome.storage && chrome.storage.session) {
        const stored = await chrome.storage.session.get(SESSION_STORAGE_KEY);
        const serialized = stored && stored[SESSION_STORAGE_KEY];
        if (serialized && typeof serialized === 'object') {
          const sameEngineVersion = Boolean(
            serialized._meta && serialized._meta.detectorEngineVersion === DETECTOR_ENGINE_VERSION
          );
          if (serialized._meta && serialized._meta.lastSourceTab && typeof serialized._meta.lastSourceTab === 'object') {
            lastSourceTab = {
              tabId: serialized._meta.lastSourceTab.tabId ?? null,
              url: serialized._meta.lastSourceTab.url || '',
            };
          }
          for (const [key, val] of Object.entries(serialized)) {
            if (key === '_meta') continue;
            const numericId = Number(key);
            if (!Number.isNaN(numericId) && val && typeof val === 'object') {
              const restored = { ...createEmptyTabState(), ...val };
              if (!sameEngineVersion) {
                restored.lastAnalyzedUrl = '';
                restored.lastRawUrl = '';
                restored.lastAnalyzedAt = 0;
                restored.lastResult = null;
                restored.pendingWarning = null;
              }
              tabStates.set(numericId, restored);
            }
          }
        }
      }
    } catch (_) {
      // Session storage may be unavailable in restricted contexts; fall back to in-memory state.
    }
  })();
  return hydrationPromise;
}

async function persistTabStates() {
  try {
    if (!chrome.storage || !chrome.storage.session) return;
    const obj = {};
    for (const [tabId, state] of tabStates.entries()) {
      // Store compact result without bulky intermediate feature objects if huge
      const compactState = {
        ...state,
        lastResult: state.lastResult
          ? { ...state.lastResult, features: undefined }
          : null,
        pendingWarning: state.pendingWarning
          ? {
              ...state.pendingWarning,
              result: state.pendingWarning.result
                ? { ...state.pendingWarning.result, features: undefined }
                : null,
            }
          : null,
      };
      obj[String(tabId)] = compactState;
    }
    obj._meta = { lastSourceTab, detectorEngineVersion: DETECTOR_ENGINE_VERSION };
    await chrome.storage.session.set({ [SESSION_STORAGE_KEY]: obj });
  } catch (_) {
    // Non-fatal if session storage quota/context rejects.
  }
}

function getOrCreateTabState(tabId) {
  if (!tabStates.has(tabId)) {
    tabStates.set(tabId, createEmptyTabState());
  }
  return tabStates.get(tabId);
}

const ICON_SETS = {
  default: {
    16: 'icons/icon-default-16.png',
    32: 'icons/icon-default-32.png',
    48: 'icons/icon-default-48.png',
    128: 'icons/icon-default-128.png',
  },
  safe: {
    16: 'icons/icon-safe-16.png',
    32: 'icons/icon-safe-32.png',
    48: 'icons/icon-safe-48.png',
    128: 'icons/icon-safe-128.png',
  },
  warning: {
    16: 'icons/icon-warning-16.png',
    32: 'icons/icon-warning-32.png',
    48: 'icons/icon-warning-48.png',
    128: 'icons/icon-warning-128.png',
  },
  danger: {
    16: 'icons/icon-danger-16.png',
    32: 'icons/icon-danger-32.png',
    48: 'icons/icon-danger-48.png',
    128: 'icons/icon-danger-128.png',
  },
};

function getHostnameForUrl(rawUrl) {
  const normalized = PhishGuardURLAnalyzer.normalizeUrl(rawUrl);
  return normalized ? normalized.hostname.toLowerCase() : '';
}

const VALID_OUTCOMES = new Set(['SAFE', 'SUSPICIOUS', 'PHISHING', 'UNVERIFIED']);

function buildVerificationFailedResult(targetUrl, reason) {
  return {
    supported: true,
    valid: false,
    verificationFailed: true,
    url: String(targetUrl || ''),
    displayUrl: String(targetUrl || 'Unverified URL'),
    domain: getHostnameForUrl(targetUrl),
    detectedDomain: getHostnameForUrl(targetUrl),
    hostname: getHostnameForUrl(targetUrl),
    impersonatedBrand: null,
    uiState: 'phishing',
    outcome: 'UNVERIFIED',
    classification: 'UNVERIFIED',
    riskBadge: 'UNVERIFIED',
    classificationLabel: 'Unverified (Verification Failed)',
    shouldBlock: true,
    riskScore: 0,
    riskLevel: 'Unverified',
    severity: 'unknown',
    headerSubtitle: '⚠️ Caution: Verification Failed',
    statusTitle: 'Unable to Verify URL',
    statusDetail:
      reason ||
      'URL verification failed due to a technical error or insufficient analysis data. PhishGuard cannot confirm whether this site is safe or phishing.',
    checksHeading: 'Verification details',
    checks: [
      { name: 'URL verification', status: 'Failed', type: 'passed' },
      { name: 'Confirmed phishing indicators', status: 'None confirmed', type: 'passed' },
    ],
    recommendation:
      'Verification could not be completed. Confirm the website destination independently before entering passwords or sensitive details.',
    reasons: [],
    indicators: [],
    rules: [],
  };
}

function isExemptResult(result) {
  return Boolean(
    result &&
      typeof result === 'object' &&
      (result.exempt ||
        result.isInternalBrowserPage ||
        result.classification === 'EXEMPT' ||
        result.outcome === 'EXEMPT')
  );
}

function classifyUrlScope(rawUrl) {
  if (
    PhishGuardURLAnalyzer &&
    typeof PhishGuardURLAnalyzer.classifyExemptUrl === 'function'
  ) {
    return PhishGuardURLAnalyzer.classifyExemptUrl(rawUrl);
  }
  const trimmed = String(rawUrl || '').trim();
  const isExempt =
    /^(chrome|chrome-extension|extension|edge|chrome-search|chrome-devtools|chrome-untrusted|devtools|brave|opera|vivaldi|about|file):/i.test(
      trimmed
    );
  return { isExempt, isInternalBrowserPage: isExempt };
}

function extractAutomaticWarningClassification(result) {
  if (!result || typeof result !== 'object') {
    return 'UNVERIFIED';
  }
  if (isExemptResult(result)) {
    return 'EXEMPT';
  }
  const rawOutcome = typeof result.outcome === 'string' ? result.outcome : result.classification;
  if (typeof rawOutcome === 'string' && VALID_OUTCOMES.has(rawOutcome)) {
    return rawOutcome;
  }
  if (result.riskLevel === 'Safe' && (!rawOutcome || rawOutcome === 'Safe' || rawOutcome === 'safe')) {
    return 'SAFE';
  }
  if (result.classification === 'phishing' || result.riskLevel === 'High Risk') {
    return 'PHISHING';
  }
  if (
    result.classification === 'suspicious' ||
    result.riskLevel === 'Suspicious' ||
    result.riskLevel === 'Medium Risk'
  ) {
    return 'SUSPICIOUS';
  }
  return 'UNVERIFIED';
}

function shouldOpenAutomaticWarning(outcome) {
  if (outcome === 'SAFE') {
    // Allow normal browsing without opening the warning interface.
    return false;
  } else {
    // Open the warning interface for SUSPICIOUS, PHISHING, or UNVERIFIED outcomes.
    return true;
  }
}

async function syncPopupForTab(tabId, result, isDismissed, options) {
  if (typeof tabId !== 'number' || tabId < 0) return;
  if (!chrome.action || typeof chrome.action.setPopup !== 'function') return;
  try {
    const isWarningTab = Boolean(options && options.isWarningTab);
    const isExemptPage = isExemptResult(result);
    const outcome = extractAutomaticWarningClassification(result);
    const shouldWarn = !isExemptPage && shouldOpenAutomaticWarning(outcome);
    const shouldSuppressPopup =
      isWarningTab || (!isExemptPage && shouldWarn && !isDismissed);
    await chrome.action.setPopup({
      tabId,
      popup: shouldSuppressPopup ? '' : POPUP_PAGE_PATH,
    });
  } catch (_) {
    // Ignore closed tab or unsupported setPopup
  }
}

async function updateActionForTab(tabId, result, isDismissed, options) {
  if (typeof tabId !== 'number' || tabId < 0) return;
  await syncPopupForTab(tabId, result, isDismissed, options);
  try {
    if (!result || isExemptResult(result)) {
      if (chrome.action.setIcon) {
        await chrome.action.setIcon({ tabId, path: ICON_SETS.default });
      }
      await chrome.action.setBadgeText({ tabId, text: '' });
      await chrome.action.setTitle({
        tabId,
        title:
          (result && (result.extensionTitle || result.statusTitle)) ||
          'PhishGuard – Exempt page (not scanned)',
      });
      return;
    }

    const outcome = extractAutomaticWarningClassification(result);
    if (outcome === 'PHISHING') {
      if (chrome.action.setIcon) {
        await chrome.action.setIcon({ tabId, path: ICON_SETS.danger });
      }
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#dc2626' });
      await chrome.action.setBadgeText({ tabId, text: isDismissed ? '!' : '' });
      await chrome.action.setTitle({
        tabId,
        title: isDismissed
          ? 'PhishGuard – Phishing Warning Dismissed'
          : 'PhishGuard – Phishing Indicators Detected',
      });
      return;
    }

    if (outcome === 'SUSPICIOUS') {
      if (chrome.action.setIcon) {
        await chrome.action.setIcon({ tabId, path: ICON_SETS.warning });
      }
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#d97706' });
      await chrome.action.setBadgeText({ tabId, text: '' });
      await chrome.action.setTitle({
        tabId,
        title: 'PhishGuard – Suspicious URL Indicators Detected',
      });
      return;
    }

    if (outcome === 'SAFE') {
      if (chrome.action.setIcon) {
        await chrome.action.setIcon({ tabId, path: ICON_SETS.safe });
      }
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#15803d' });
      await chrome.action.setBadgeText({ tabId, text: '' });
      await chrome.action.setTitle({
        tabId,
        title: 'PhishGuard – Safe: No Suspicious Indicators Found',
      });
      return;
    }

    if (chrome.action.setIcon) {
      await chrome.action.setIcon({ tabId, path: ICON_SETS.warning });
    }
    await chrome.action.setBadgeBackgroundColor({ tabId, color: '#d97706' });
    await chrome.action.setBadgeText({ tabId, text: '?' });
    await chrome.action.setTitle({
      tabId,
      title: 'PhishGuard – Unverified: Verification Failed',
    });
  } catch (_) {
    // Tab may have already closed.
  }
}

async function setLoadingActionForTab(tabId, url) {
  if (typeof tabId !== 'number' || tabId < 0) return;
  await syncPopupForTab(tabId, null, false);
  try {
    if (chrome.action.setIcon) {
      await chrome.action.setIcon({ tabId, path: ICON_SETS.default });
    }
    await chrome.action.setBadgeText({ tabId, text: '' });
    await chrome.action.setTitle({
      tabId,
      title: `PhishGuard – Scanning ${url ? getHostnameForUrl(url) || 'page' : 'page'}...`,
    });
  } catch (_) {
    // Tab may have closed.
  }
}

async function redirectTabToWarning(tabId, targetUrl) {
  const now = Date.now();
  const lock = redirectLocks.get(tabId);
  if (lock && lock.targetUrl === targetUrl && now - lock.at < REDIRECT_LOCK_MS) {
    return false;
  }
  redirectLocks.set(tabId, { targetUrl, at: now });
  try {
    const liveTab = await chrome.tabs.get(tabId);
    if (liveTab && isWarningPageUrl(liveTab.url)) {
      const existingParams = parseWarningParams(liveTab.url);
      if (existingParams.targetUrl === targetUrl) {
        return false;
      }
    }
  } catch (_) {
    // If tabs.get fails temporarily, proceed with tabs.update attempt
  }

  const warningUrl =
    `${getWarningPageBaseUrl()}?mode=warning&tabId=${encodeURIComponent(String(tabId))}` +
    `&url=${encodeURIComponent(targetUrl)}`;

  try {
    await chrome.tabs.update(tabId, { url: warningUrl });
    return true;
  } catch (_) {
    return false;
  }
}

async function evaluateTabNavigation(tabId, rawUrl, options = {}) {
  if (typeof tabId !== 'number' || tabId < 0) return null;
  await ensureHydrated();

  const state = getOrCreateTabState(tabId);

  // Preserve active pending blocking warning if Chromium transitioned to chrome-error://chromewebdata/
  if (typeof rawUrl === 'string' && rawUrl.startsWith('chrome-error://') && state.pendingWarning && state.pendingWarning.targetUrl) {
    const blockedUrl = state.pendingWarning.targetUrl || state.currentUrl;
    let freshBlockedResult = null;
    try {
      freshBlockedResult = PhishGuardDetector.analyzeUrl(blockedUrl);
    } catch (_) {
      freshBlockedResult = null;
    }
    const blockedHost = (freshBlockedResult && freshBlockedResult.hostname) || getHostnameForUrl(blockedUrl);
    const isDismissed = Boolean(blockedHost && state.dismissedHostnames.includes(blockedHost));
    const shouldWarnBlocked = shouldOpenAutomaticWarning(
      extractAutomaticWarningClassification(freshBlockedResult)
    );
    if (shouldWarnBlocked && !isDismissed && !options.skipRedirect) {
      await redirectTabToWarning(tabId, blockedUrl);
    }
    return freshBlockedResult;
  }

  // Never trigger detection on the extension's own warning, status, or scanner interfaces
  if (isWarningPageUrl(rawUrl)) {
    const params = parseWarningParams(rawUrl);
    if (params.mode === 'scanner') {
      await updateActionForTab(tabId, buildExtensionUiPageMeta('PhishGuard – Manual URL Scanner'), false);
      return null;
    }
    const isWarningTab = params.mode === 'warning';
    const targetState =
      typeof params.tabId === 'number' ? tabStates.get(params.tabId) || null : null;
    const underlyingUrl =
      params.targetUrl ||
      (targetState && targetState.currentUrl) ||
      (state.pendingWarning && state.pendingWarning.targetUrl) ||
      '';
    if (underlyingUrl && !isExtensionUiPageUrl(underlyingUrl)) {
      const evaluated = PhishGuardDetector.analyzeUrl(underlyingUrl);
      const host = (evaluated && evaluated.hostname) || getHostnameForUrl(underlyingUrl);
      const isDismissed = Boolean(
        host && targetState && Array.isArray(targetState.dismissedHostnames) && targetState.dismissedHostnames.includes(host)
      );
      await updateActionForTab(tabId, evaluated, isDismissed, { isWarningTab });
      return evaluated;
    }
    await updateActionForTab(tabId, buildExtensionUiPageMeta(), false, { isWarningTab });
    return null;
  }

  if (isScannerPageUrl(rawUrl) || isExtensionUiPageUrl(rawUrl)) {
    await updateActionForTab(tabId, buildExtensionUiPageMeta('PhishGuard – Manual URL Scanner'), false);
    return null;
  }

  // Exempt internal browser, extension, built-in PDF viewer, and local file:// URLs BEFORE detection.
  const urlScope = classifyUrlScope(rawUrl);
  if (urlScope.isExempt || !PhishGuardURLAnalyzer.isSupportedUrl(rawUrl)) {
    const isEmptyOrBlank = !rawUrl || typeof rawUrl !== 'string' || !rawUrl.trim();
    let unsupportedResult = null;
    try {
      unsupportedResult = PhishGuardDetector.analyzeUrl(rawUrl);
    } catch (_) {
      unsupportedResult = buildVerificationFailedResult(rawUrl, 'Unable to inspect browser URL.');
    }
    state.currentUrl = rawUrl || '';
    state.lastAnalyzedUrl = rawUrl || '';
    state.lastAnalyzedAt = Date.now();
    state.lastResult = unsupportedResult;
    state.pendingWarning = null;
    redirectLocks.delete(tabId);
    if (isEmptyOrBlank || urlScope.isExempt || isExemptResult(unsupportedResult)) {
      await updateActionForTab(tabId, isEmptyOrBlank ? buildExtensionUiPageMeta() : unsupportedResult, false);
      await persistTabStates();
      return { ...(unsupportedResult || {}), dismissed: false, blocked: false };
    }
    // Non-exempt unsupported/malformed external URLs open the warning interface as UNVERIFIED
    if (!options.skipRedirect) {
      state.pendingWarning = {
        targetUrl: rawUrl || '',
        result: unsupportedResult,
        createdAt: Date.now(),
      };
      await redirectTabToWarning(tabId, rawUrl || '');
      await updateActionForTab(tabId, unsupportedResult, false);
      await persistTabStates();
      return { ...(unsupportedResult || {}), dismissed: false, blocked: true };
    }
    await updateActionForTab(tabId, unsupportedResult, false);
    await persistTabStates();
    return unsupportedResult;
  }

  const normalizedObj = PhishGuardURLAnalyzer.normalizeUrl(rawUrl);
  const normalizedUrl = normalizedObj ? normalizedObj.href : rawUrl;
  const detectionInput = rawUrl || normalizedUrl;
  const now = Date.now();
  const navEpoch = (tabNavEpochs.get(tabId) || 0) + 1;
  tabNavEpochs.set(tabId, navEpoch);

  const matchingSignals =
    options.pageSignals && options.pageSignalsUrl === normalizedUrl
      ? options.pageSignals
      : state.pageSignals && state.pageSignals.url === normalizedUrl
        ? state.pageSignals
        : null;

  // Independently analyze every visited URL against the general rule-based detector
  let result = null;
  try {
    result = PhishGuardDetector.analyzeUrl(detectionInput, {
      pageSignals: matchingSignals,
    });
  } catch (err) {
    result = buildVerificationFailedResult(
      detectionInput,
      `Technical error during URL analysis: ${(err && err.message) || 'unexpected failure'}.`
    );
  }

  if (!result || typeof result !== 'object') {
    result = buildVerificationFailedResult(
      detectionInput,
      'Detection engine returned insufficient analysis data.'
    );
  }

  const outcome = extractAutomaticWarningClassification(result);
  const activateWarning = shouldOpenAutomaticWarning(outcome);

  if (tabNavEpochs.get(tabId) !== navEpoch && state.currentUrl && state.currentUrl !== normalizedUrl && !activateWarning) {
    return state.lastResult;
  }

  const hostname = (result && result.hostname) || getHostnameForUrl(normalizedUrl);
  const isDismissed = Boolean(hostname && state.dismissedHostnames.includes(hostname));

  state.currentUrl = normalizedUrl;
  state.lastRawUrl = detectionInput;
  state.lastAnalyzedUrl = normalizedUrl;
  state.lastAnalyzedAt = now;
  state.lastResult = result;

  if (outcome === 'SAFE') {
    // Allow normal browsing and display Safe interface in popup.
    state.lastSafeUrl = normalizedUrl;
    state.pendingWarning = null;
    await updateActionForTab(tabId, result, false);
    await persistTabStates();
    return { ...result, dismissed: false, blocked: false };
  }

  // Open warning interface for SUSPICIOUS, PHISHING, or UNVERIFIED outcomes.
  if (!isDismissed && !options.skipRedirect) {
    state.pendingWarning = {
      targetUrl: detectionInput,
      result,
      createdAt: now,
    };
    await redirectTabToWarning(tabId, detectionInput);
    await updateActionForTab(tabId, result, false);
    await persistTabStates();
    return { ...result, dismissed: false, blocked: true };
  }

  state.pendingWarning = null;
  await updateActionForTab(tabId, result, isDismissed);
  await persistTabStates();
  return { ...result, dismissed: isDismissed, blocked: false };
}

async function navigateBackToSafety(tabId) {
  await ensureHydrated();
  const state = getOrCreateTabState(tabId);
  let safeTarget = '';

  if (state.lastSafeUrl && PhishGuardURLAnalyzer.isSupportedUrl(state.lastSafeUrl)) {
    const check = PhishGuardDetector.analyzeUrl(state.lastSafeUrl);
    if (!shouldOpenAutomaticWarning(extractAutomaticWarningClassification(check))) {
      safeTarget = state.lastSafeUrl;
    }
  }

  state.pendingWarning = null;
  state.lastAnalyzedUrl = '';
  state.lastAnalyzedAt = 0;
  redirectLocks.delete(tabId);
  await persistTabStates();

  if (safeTarget) {
    try {
      await chrome.tabs.update(tabId, { url: safeTarget });
      return safeTarget;
    } catch (_) {
      // Fallback below
    }
  }

  const fallbacks = ['chrome://newtab/', 'about:blank'];
  for (const dest of fallbacks) {
    try {
      await chrome.tabs.update(tabId, { url: dest });
      return dest;
    } catch (_) {
      // Try next fallback
    }
  }
  return '';
}

// ============================================================================
// Chrome Extension Lifecycle & Navigation Listeners (registered synchronously)
// ============================================================================

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  evaluateTabNavigation(details.tabId, details.url, { source: 'onBeforeNavigate' });
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  const isReload = details.transitionType === 'reload';
  evaluateTabNavigation(details.tabId, details.url, {
    source: 'onCommitted',
    force: isReload,
  });
});

chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId !== 0) return;
  evaluateTabNavigation(details.tabId, details.url, { source: 'onHistoryStateUpdated' });
});

chrome.webNavigation.onReferenceFragmentUpdated.addListener((details) => {
  if (details.frameId !== 0) return;
  evaluateTabNavigation(details.tabId, details.url, { source: 'onReferenceFragmentUpdated' });
});

if (chrome.webNavigation.onErrorOccurred && typeof chrome.webNavigation.onErrorOccurred.addListener === 'function') {
  chrome.webNavigation.onErrorOccurred.addListener((details) => {
    if (details.frameId !== 0) return;
    if (details.url && PhishGuardURLAnalyzer.isSupportedUrl(details.url)) {
      evaluateTabNavigation(details.tabId, details.url, { source: 'onErrorOccurred' });
    }
  });
}

if (chrome.tabs.onReplaced && typeof chrome.tabs.onReplaced.addListener === 'function') {
  chrome.tabs.onReplaced.addListener((addedTabId) => {
    (async () => {
      try {
        const tab = await chrome.tabs.get(addedTabId);
        if (tab && tab.url) {
          await evaluateTabNavigation(addedTabId, tab.url, { source: 'tabs.onReplaced' });
        }
      } catch (_) {
        // Ignore non-existent replaced tab
      }
    })();
  });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    evaluateTabNavigation(tabId, changeInfo.url, { source: 'tabs.onUpdated.url' });
    return;
  }

  if ((changeInfo.status === 'loading' || changeInfo.status === 'complete') && tab && tab.url) {
    (async () => {
      await ensureHydrated();
      const state = getOrCreateTabState(tabId);
      const normalized = PhishGuardURLAnalyzer.normalizeUrl(tab.url)?.href || tab.url;
      const host = (state.lastResult && state.lastResult.hostname) || getHostnameForUrl(tab.url);
      const isDismissed = Boolean(host && state.dismissedHostnames.includes(host));
      const needsWarningRedirect =
        PhishGuardURLAnalyzer.isSupportedUrl(tab.url) &&
        !isExemptResult(state.lastResult) &&
        shouldOpenAutomaticWarning(extractAutomaticWarningClassification(state.lastResult)) &&
        !isDismissed;
      if (!state.lastResult || state.lastAnalyzedUrl !== normalized || needsWarningRedirect) {
        await evaluateTabNavigation(tabId, tab.url, { source: `tabs.onUpdated.${changeInfo.status}` });
      } else {
        await updateActionForTab(tabId, state.lastResult, isDismissed);
      }
    })();
  }
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  (async () => {
    await ensureHydrated();
    const state = getOrCreateTabState(tabId);
    try {
      const tab = await chrome.tabs.get(tabId);
      if (tab && tab.url) {
        if (!isExtensionUiPageUrl(tab.url)) {
          lastSourceTab = { tabId, url: tab.url };
        }
        const normalized = PhishGuardURLAnalyzer.normalizeUrl(tab.url)?.href || tab.url;
        if (state.lastResult && state.lastAnalyzedUrl === normalized && !isExtensionUiPageUrl(tab.url)) {
          const host = state.lastResult.hostname || getHostnameForUrl(state.currentUrl);
          const isDismissed = Boolean(host && state.dismissedHostnames.includes(host));
          const needsWarningRedirect =
            PhishGuardURLAnalyzer.isSupportedUrl(tab.url) &&
            !isExemptResult(state.lastResult) &&
            shouldOpenAutomaticWarning(extractAutomaticWarningClassification(state.lastResult)) &&
            !isDismissed;
          if (!needsWarningRedirect) {
            await updateActionForTab(tabId, state.lastResult, isDismissed);
            return;
          }
        }
        await evaluateTabNavigation(tabId, tab.url, { source: 'tabs.onActivated' });
        return;
      }
    } catch (_) {
      // Ignore closed/unaccessible tab
    }

    if (state.lastResult) {
      const host = state.lastResult.hostname || getHostnameForUrl(state.currentUrl);
      const isDismissed = Boolean(host && state.dismissedHostnames.includes(host));
      await updateActionForTab(tabId, state.lastResult, isDismissed);
    }
  })();
});

async function focusTabAndWindow(tab) {
  if (!tab || typeof tab.id !== 'number') return;
  try {
    await chrome.tabs.update(tab.id, { active: true });
  } catch (_) {
    // Tab may have closed
  }
  if (chrome.windows && chrome.windows.update && typeof tab.windowId === 'number') {
    try {
      await chrome.windows.update(tab.windowId, { focused: true });
    } catch (_) {
      // Window focus optional
    }
  }
}

async function openOrFocusFullTabInterface(clickedTab) {
  await ensureHydrated();

  let sourceTab = clickedTab || null;
  if (!sourceTab || typeof sourceTab.id !== 'number') {
    try {
      const activeTabs = await chrome.tabs.query({ active: true, currentWindow: true });
      sourceTab = (activeTabs && activeTabs[0]) || null;
    } catch (_) {
      sourceTab = null;
    }
  }

  const clickedUrl = (sourceTab && sourceTab.url) || '';

  // If user clicked the toolbar icon while already viewing an automatic warning, status, or scanner tab,
  // focus/keep that existing PhishGuard tab instead of spawning a duplicate tab.
  if (sourceTab && isExtensionUiPageUrl(clickedUrl)) {
    const selfParams = parseWarningParams(clickedUrl);
    if (isWarningPageUrl(clickedUrl) && selfParams.mode !== 'warning' && typeof chrome.tabs.sendMessage === 'function') {
      try {
        await chrome.tabs.sendMessage(sourceTab.id, {
          type: 'PHISHGUARD_SYNC_STATUS_TAB',
          targetTabId: selfParams.tabId,
          targetUrl: selfParams.targetUrl,
          statusUrl: clickedUrl,
        });
      } catch (_) {
        // Tab listener might not be active yet
      }
    }
    await focusTabAndWindow(sourceTab);
    return { reused: true, tabId: sourceTab.id };
  }

  const targetTabId = sourceTab && typeof sourceTab.id === 'number' ? sourceTab.id : null;
  const targetUrl = clickedUrl;

  if (targetTabId !== null) {
    lastSourceTab = { tabId: targetTabId, url: targetUrl };
    const st = getOrCreateTabState(targetTabId);
    const normalizedTarget = PhishGuardURLAnalyzer.normalizeUrl(targetUrl)?.href || targetUrl;
    if (!st.lastResult || st.lastAnalyzedUrl !== normalizedTarget) {
      await evaluateTabNavigation(targetTabId, targetUrl, {
        source: 'toolbar_click',
        skipRedirect: true,
      });
    }
    const evaluatedState = getOrCreateTabState(targetTabId);
    const host = (evaluatedState.lastResult && evaluatedState.lastResult.hostname) || getHostnameForUrl(targetUrl);
    const isDismissed = Boolean(host && evaluatedState.dismissedHostnames.includes(host));
    const shouldWarn =
      !isExemptResult(evaluatedState.lastResult) &&
      shouldOpenAutomaticWarning(
        extractAutomaticWarningClassification(evaluatedState.lastResult)
      );
    if (PhishGuardURLAnalyzer.isSupportedUrl(targetUrl) && shouldWarn && !isDismissed) {
      await redirectTabToWarning(targetTabId, normalizedTarget || targetUrl);
      return { redirectedToWarning: true, tabId: targetTabId };
    }
  }

  const statusUrl = buildStatusTabUrl(targetTabId, targetUrl);
  let existingStatusTab = null;

  try {
    const allTabs = await chrome.tabs.query({});
    const statusTabs = allTabs.filter((t) => {
      if (!t || typeof t.url !== 'string' || !isWarningPageUrl(t.url)) return false;
      return parseWarningParams(t.url).mode !== 'warning';
    });
    if (statusTabs.length > 0) {
      const sameWindow = sourceTab && typeof sourceTab.windowId === 'number'
        ? statusTabs.find((t) => t.windowId === sourceTab.windowId)
        : null;
      existingStatusTab = sameWindow || statusTabs[0];
    }
  } catch (_) {
    existingStatusTab = null;
  }

  if (existingStatusTab && typeof existingStatusTab.id === 'number') {
    let syncedInPlace = false;
    if (typeof chrome.tabs.sendMessage === 'function') {
      try {
        const ack = await new Promise((resolve) => {
          let settled = false;
          const finish = (ok) => {
            if (settled) return;
            settled = true;
            resolve(ok);
          };
          const timer = setTimeout(() => finish(false), 150);
          chrome.tabs.sendMessage(
            existingStatusTab.id,
            {
              type: 'PHISHGUARD_SYNC_STATUS_TAB',
              targetTabId,
              targetUrl,
              statusUrl,
            },
            (resp) => {
              clearTimeout(timer);
              if (chrome.runtime.lastError || !resp || !resp.ok) {
                finish(false);
                return;
              }
              finish(true);
            }
          );
        });
        syncedInPlace = Boolean(ack);
      } catch (_) {
        syncedInPlace = false;
      }
    }

    if (syncedInPlace) {
      await focusTabAndWindow(existingStatusTab);
    } else {
      await chrome.tabs.update(existingStatusTab.id, { url: statusUrl, active: true });
      if (chrome.windows && chrome.windows.update && typeof existingStatusTab.windowId === 'number') {
        try {
          await chrome.windows.update(existingStatusTab.windowId, { focused: true });
        } catch (_) {
          // Optional
        }
      }
    }
    if (targetTabId !== null && tabStates.has(targetTabId)) {
      const targetState = tabStates.get(targetTabId);
      const host = (targetState.lastResult && targetState.lastResult.hostname) || getHostnameForUrl(targetUrl);
      const isDismissed = Boolean(host && targetState.dismissedHostnames.includes(host));
      await updateActionForTab(existingStatusTab.id, targetState.lastResult, isDismissed);
    }
    return { reused: true, tabId: existingStatusTab.id, statusUrl };
  }

  await persistTabStates();
  const createProps = {
    url: statusUrl,
    active: true,
  };
  if (sourceTab && typeof sourceTab.windowId === 'number') {
    createProps.windowId = sourceTab.windowId;
  }
  if (sourceTab && typeof sourceTab.index === 'number') {
    createProps.index = sourceTab.index + 1;
  }
  const created = await chrome.tabs.create(createProps);
  if (created && typeof created.id === 'number' && targetTabId !== null && tabStates.has(targetTabId)) {
    const targetState = tabStates.get(targetTabId);
    const host = (targetState.lastResult && targetState.lastResult.hostname) || getHostnameForUrl(targetUrl);
    const isDismissed = Boolean(host && targetState.dismissedHostnames.includes(host));
    await updateActionForTab(created.id, targetState.lastResult, isDismissed);
  }
  return { reused: false, tabId: created && created.id, statusUrl };
}

if (chrome.action && chrome.action.onClicked && typeof chrome.action.onClicked.addListener === 'function') {
  chrome.action.onClicked.addListener((clickedTab) => {
    // Chain rapid clicks sequentially so repeated clicks coalesce onto a single status tab
    actionClickQueue = actionClickQueue
      .catch(() => null)
      .then(() => openOrFocusFullTabInterface(clickedTab));
  });
}

chrome.tabs.onRemoved.addListener((tabId) => {
  (async () => {
    await ensureHydrated();
    tabStates.delete(tabId);
    redirectLocks.delete(tabId);
    await persistTabStates();
  })();
});

async function scanExistingOpenTabs() {
  await ensureHydrated();
  try {
    const tabs = await chrome.tabs.query({});
    for (const tab of tabs) {
      if (tab && typeof tab.id === 'number' && tab.url) {
        await evaluateTabNavigation(tab.id, tab.url, {
          source: 'startup_scan',
          skipRedirect: true,
        });
      }
    }
  } catch (_) {
    // Ignore tab query errors during startup
  }
}

chrome.runtime.onInstalled.addListener(() => {
  scanExistingOpenTabs();
});

chrome.runtime.onStartup.addListener(() => {
  scanExistingOpenTabs();
});

// ============================================================================
// Extension Messaging Hub (content.js <-> background.js <-> index.html/app.js)
// ============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== 'string') {
    return false;
  }

  (async () => {
    await ensureHydrated();

    switch (message.type) {
      case 'PHISHGUARD_CONTENT_URL': {
        const senderTabId = sender.tab && typeof sender.tab.id === 'number' ? sender.tab.id : null;
        if (senderTabId === null || (sender.frameId !== undefined && sender.frameId !== 0)) {
          sendResponse({ ok: false });
          return;
        }
        const url = message.url || (sender.tab && sender.tab.url) || '';
        const result = await evaluateTabNavigation(senderTabId, url, {
          source: 'content_url',
          force: message.event === 'reload',
        });
        sendResponse({ ok: true, result });
        return;
      }

      case 'PHISHGUARD_PAGE_SIGNALS': {
        const senderTabId = sender.tab && typeof sender.tab.id === 'number' ? sender.tab.id : null;
        if (senderTabId === null || (sender.frameId !== undefined && sender.frameId !== 0)) {
          sendResponse({ ok: false });
          return;
        }
        const state = getOrCreateTabState(senderTabId);
        const url = message.url || (sender.tab && sender.tab.url) || '';
        if (!url || !PhishGuardURLAnalyzer.isSupportedUrl(url) || classifyUrlScope(url).isExempt) {
          sendResponse({ ok: true, exempt: true });
          return;
        }
        state.pageSignals = {
          url,
          hasPasswordField: Boolean(message.signals && message.signals.hasPasswordField),
          hasCrossOriginForm: Boolean(message.signals && message.signals.hasCrossOriginForm),
        };
        const result = await evaluateTabNavigation(senderTabId, url, {
          source: 'page_signals',
          force: true,
          pageSignals: state.pageSignals,
          pageSignalsUrl: url,
        });
        sendResponse({ ok: true, result });
        return;
      }

      case 'PHISHGUARD_GET_LAST_TARGET_TAB': {
        let resolvedTabId = lastSourceTab.tabId;
        let resolvedUrl = lastSourceTab.url || '';
        if (resolvedTabId !== null) {
          try {
            const liveTab = await chrome.tabs.get(resolvedTabId);
            if (liveTab && liveTab.url && !isExtensionUiPageUrl(liveTab.url)) {
              resolvedUrl = liveTab.url;
            } else {
              resolvedTabId = null;
              resolvedUrl = '';
            }
          } catch (_) {
            // Stale closed source tab must not trigger detection/redirects for unrelated pages
            resolvedTabId = null;
            resolvedUrl = '';
          }
        }
        if (resolvedTabId === null) {
          try {
            const tabs = await chrome.tabs.query({});
            const fallback = tabs.find(
              (t) =>
                t &&
                t.url &&
                !isExtensionUiPageUrl(t.url) &&
                PhishGuardURLAnalyzer.isSupportedUrl(t.url)
            );
            if (fallback) {
              resolvedTabId = fallback.id;
              resolvedUrl = fallback.url || '';
            }
          } catch (_) {
            // Ignore query failure
          }
        }
        if (isExtensionUiPageUrl(resolvedUrl)) {
          resolvedUrl = '';
        }
        sendResponse({ ok: true, targetTabId: resolvedTabId, targetUrl: resolvedUrl });
        return;
      }

      case 'PHISHGUARD_GET_TAB_STATUS': {
        const tabId = typeof message.tabId === 'number' ? message.tabId : null;
        let targetUrl = message.url || '';
        let fromWarningPage = Boolean(message.fromWarningPage);
        const fromStatusTab = Boolean(message.fromStatusTab);

        if (isWarningPageUrl(targetUrl)) {
          const parsed = parseWarningParams(targetUrl);
          if (parsed.mode === 'warning') fromWarningPage = true;
          if (parsed.mode === 'scanner') {
            sendResponse({
              ok: true,
              result: buildExtensionUiPageMeta('PhishGuard – Manual URL Scanner'),
              dismissed: false,
              isWarningPage: false,
              lastSafeUrl: '',
            });
            return;
          }
          targetUrl = parsed.targetUrl || '';
        } else if (isExtensionUiPageUrl(targetUrl)) {
          sendResponse({
            ok: true,
            result: buildExtensionUiPageMeta('PhishGuard – Manual URL Scanner'),
            dismissed: false,
            isWarningPage: false,
            lastSafeUrl: '',
          });
          return;
        }

        if (tabId === null) {
          const direct = PhishGuardDetector.analyzeUrl(targetUrl);
          sendResponse({
            ok: true,
            result: direct,
            dismissed: false,
            isWarningPage: fromWarningPage,
            lastSafeUrl: '',
          });
          return;
        }

        const state = getOrCreateTabState(tabId);

        if ((fromWarningPage || fromStatusTab) && !targetUrl && state.pendingWarning) {
          targetUrl = state.pendingWarning.targetUrl;
        }
        if (fromStatusTab && !targetUrl && state.currentUrl) {
          targetUrl = state.currentUrl;
        }

        if (!targetUrl && tabId !== null) {
          try {
            const liveTab = await chrome.tabs.get(tabId);
            if (liveTab && isExtensionUiPageUrl(liveTab.url || '')) {
              sendResponse({
                ok: true,
                result: buildExtensionUiPageMeta('PhishGuard – Extension Interface'),
                dismissed: false,
                isWarningPage: false,
                lastSafeUrl: state.lastSafeUrl || '',
              });
              return;
            }
          } catch (_) {
            // Ignore tab lookup failure
          }
        }

        const normalizedTarget = PhishGuardURLAnalyzer.normalizeUrl(targetUrl)?.href || targetUrl;
        const result = await evaluateTabNavigation(tabId, targetUrl, {
          source: 'popup_or_warning',
          skipRedirect: fromWarningPage || fromStatusTab,
        });

        const host = (result && result.hostname) || getHostnameForUrl(normalizedTarget);
        const dismissed = Boolean(host && state.dismissedHostnames.includes(host));

        sendResponse({
          ok: true,
          result,
          dismissed,
          isWarningPage: fromWarningPage,
          lastSafeUrl: state.lastSafeUrl || '',
        });
        return;
      }

      case 'PHISHGUARD_REANALYZE_URL': {
        const tabId = typeof message.tabId === 'number' ? message.tabId : null;
        const url = message.url || '';
        if (tabId === null) {
          sendResponse({ ok: true, result: PhishGuardDetector.analyzeUrl(url) });
          return;
        }
        const result = await evaluateTabNavigation(tabId, url, {
          source: 'manual_reanalyze',
          force: true,
          skipRedirect: Boolean(message.skipRedirect),
        });
        const state = getOrCreateTabState(tabId);
        const host = (result && result.hostname) || getHostnameForUrl(url);
        const dismissed = Boolean(host && state.dismissedHostnames.includes(host));
        sendResponse({
          ok: true,
          result,
          dismissed,
          lastSafeUrl: state.lastSafeUrl || '',
        });
        return;
      }

      case 'PHISHGUARD_BACK_TO_SAFETY': {
        const tabId = typeof message.tabId === 'number' ? message.tabId : null;
        if (tabId === null) {
          sendResponse({ ok: false, error: 'Missing tabId' });
          return;
        }
        const navigatedTo = await navigateBackToSafety(tabId);
        sendResponse({ ok: true, navigatedTo });
        return;
      }

      case 'PHISHGUARD_DISMISS_WARNING': {
        const tabId = typeof message.tabId === 'number' ? message.tabId : null;
        const targetUrl = message.url || '';
        if (tabId === null || !targetUrl) {
          sendResponse({ ok: false, error: 'Missing tabId or target URL' });
          return;
        }

        const state = getOrCreateTabState(tabId);
        const host = getHostnameForUrl(targetUrl);
        if (host && !state.dismissedHostnames.includes(host)) {
          state.dismissedHostnames.push(host);
        }
        state.pendingWarning = null;
        redirectLocks.delete(tabId);
        await persistTabStates();

        const currentResult = PhishGuardDetector.analyzeUrl(targetUrl);
        await updateActionForTab(tabId, currentResult, true);

        let redirected = false;
        try {
          const tab = await chrome.tabs.get(tabId);
          if (tab && isWarningPageUrl(tab.url)) {
            await chrome.tabs.update(tabId, { url: targetUrl });
            redirected = true;
          }
        } catch (_) {
          // Ignore if tab closed
        }

        sendResponse({ ok: true, dismissed: true, redirected });
        return;
      }

      case 'PHISHGUARD_REENABLE_PROTECTION': {
        const tabId = typeof message.tabId === 'number' ? message.tabId : null;
        const targetUrl = message.url || '';
        if (tabId === null) {
          sendResponse({ ok: false, error: 'Missing tabId' });
          return;
        }
        const state = getOrCreateTabState(tabId);
        const host = getHostnameForUrl(targetUrl);
        state.dismissedHostnames = state.dismissedHostnames.filter((h) => h !== host);
        state.pendingWarning = null;
        redirectLocks.delete(tabId);
        await persistTabStates();

        const result = await evaluateTabNavigation(tabId, targetUrl, {
          source: 'reenable_protection',
          force: true,
        });
        sendResponse({ ok: true, result });
        return;
      }

      case 'PHISHGUARD_MANUAL_SCAN': {
        // Strictly analyzes the submitted URL string without visiting, fetching, or mutating tabs,
        // preserving raw encodings/escapes before WHATWG normalization drops obfuscation evidence.
        const candidateUrl = typeof message.url === 'string' ? message.url.trim() : '';
        if (!candidateUrl) {
          sendResponse({ ok: false, error: 'Empty URL submitted for scanning.' });
          return;
        }
        if (isExtensionUiPageUrl(candidateUrl) || candidateUrl.toLowerCase().startsWith('chrome-extension://')) {
          sendResponse({ ok: false, error: 'Cannot scan internal PhishGuard extension URLs.' });
          return;
        }
        let scanResult = null;
        try {
          scanResult = PhishGuardDetector.analyzeUrl(candidateUrl);
        } catch (err) {
          scanResult = buildVerificationFailedResult(
            candidateUrl,
            `Technical error during URL analysis: ${(err && err.message) || 'unexpected failure'}.`
          );
        }
        if (!scanResult || typeof scanResult !== 'object') {
          scanResult = buildVerificationFailedResult(
            candidateUrl,
            'Detection engine returned insufficient analysis data.'
          );
        }
        sendResponse({ ok: true, result: scanResult });
        return;
      }

      default:
        sendResponse({ ok: false, error: 'Unknown message type' });
    }
  })().catch((err) => {
    sendResponse({ ok: false, error: err && err.message ? err.message : 'Internal error' });
  });

  return true;
});
