/**
 * PhishGuard Extension - UI State Controller
 * Integrates the live URL detection engine and background service worker
 * with the existing Safe and Phishing full-screen / popup interfaces.
 */

(function () {
  'use strict';

  const STATES = {
    SAFE: 'safe',
    PHISHING: 'phishing',
    NEUTRAL: 'neutral',
  };

  const ICONS = {
    statusPhishing: `
      <svg class="status-icon status-icon-warning" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 2L1 21h22L12 2z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        <line x1="12" y1="9" x2="12" y2="13" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>
        <circle cx="12" cy="17" r="1.3" fill="currentColor"/>
      </svg>
    `,
    statusNeutral: `
      <svg class="status-icon status-icon-neutral" viewBox="0 0 24 24" aria-hidden="true">
        <circle cx="12" cy="12" r="9" fill="rgba(148, 163, 184, 0.14)" stroke="#94a3b8" stroke-width="2"/>
        <line x1="12" y1="10.5" x2="12" y2="16" stroke="#cbd5e1" stroke-width="2" stroke-linecap="round"/>
        <circle cx="12" cy="7.5" r="1.15" fill="#cbd5e1"/>
      </svg>
    `,
    statusSafe:
      (window.PhishGuardTransitions && window.PhishGuardTransitions.SAFE_TICK_SVG) ||
      '<svg class="status-icon status-icon-safe" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path class="pg-safe-circle" d="M 12 3 a 9 9 0 1 1 0 18 a 9 9 0 1 1 0 -18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path class="pg-safe-check" d="M 8.85 12.15 L 10.95 14.25 L 15.15 9.75" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    checkDanger: `
      <svg class="check-icon check-icon-danger" viewBox="0 0 24 24" aria-hidden="true">
        <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/>
        <line x1="12" y1="8" x2="12" y2="12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
        <circle cx="12" cy="16" r="1" fill="currentColor"/>
      </svg>
    `,
    checkPassed: `
      <svg class="check-icon check-icon-passed" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M5 13l4 4L19 7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    `,
  };

  const DEFAULT_PREVIEW_URLS = {
    [STATES.PHISHING]: 'https://account-verify-portal.top/login',
    [STATES.SAFE]: 'https://www.example.com',
  };

  const STATE_THEME = {
    [STATES.PHISHING]: {
      pageTitle: 'PhishGuard – Phishing Detected',
      statusClass: 'status-phishing',
      statusIcon: ICONS.statusPhishing,
      bgVideoSrc: './spam_bg.mp4',
      panelBgVideoSrc: './spam_central_bg.mp4',
      showActions: true,
    },
    [STATES.SAFE]: {
      pageTitle: 'PhishGuard – Safe Site',
      statusClass: 'status-safe',
      statusIcon: ICONS.statusSafe,
      bgVideoSrc: './Citron.mp4',
      panelBgVideoSrc: './blend.mp4',
      showActions: false,
    },
    [STATES.NEUTRAL]: {
      pageTitle: 'PhishGuard – Exempt Page (Not Scanned)',
      statusClass: 'status-neutral',
      statusIcon: ICONS.statusNeutral,
      bgVideoSrc: '',
      panelBgVideoSrc: '',
      showActions: false,
    },
  };

  let currentState = STATES.NEUTRAL;
  let currentDetectionResult = null;
  let activeTabId = null;
  let activeTargetUrl = '';
  let isWarningPageMode = false;
  let isFullTabStatusMode = false;
  let isPopupMode = false;
  let isDismissedForTab = false;
  let activeInterface = 'status'; // 'status' | 'confirmation' | 'scanner'
  let hasHydratedInitialState = false;
  let lastVisualSignature = '';
  let lastThemeTone = 'neutral'; // 'safe' | 'suspicious' | 'phishing' | 'neutral'

  const elements = {};

  function getTransitions() {
    return window.PhishGuardTransitions || null;
  }

  function isExtensionRuntime() {
    return typeof chrome !== 'undefined' && Boolean(chrome.runtime && chrome.runtime.id);
  }

  function isFullTabMode() {
    return !isPopupMode && (isWarningPageMode || isFullTabStatusMode);
  }

  function initElements() {
    elements.body = document.body;
    elements.panel = document.querySelector('.extension-panel');
    elements.panelAccentWash = document.getElementById('panelAccentWash');
    elements.panelStage = document.getElementById('panelStage');
    elements.bgVideo = document.getElementById('bgVideo');
    elements.bgVideoSafe = document.getElementById('bgVideoSafe');
    elements.panelBgVideo = document.getElementById('panelBgVideo');
    elements.panelBgVideoSafe = document.getElementById('panelBgVideoSafe');
    elements.headerSubtitle = document.getElementById('headerSubtitle');
    elements.statusHeaderControls = document.getElementById('statusHeaderControls');
    elements.scannerHeaderControls = document.getElementById('scannerHeaderControls');
    elements.panelFooterText = document.getElementById('panelFooterText');
    elements.urlField = document.getElementById('currentUrlField');
    elements.statusSection = document.getElementById('statusSection');
    elements.statusIconWrapper = document.getElementById('statusIconWrapper');
    elements.statusTitle = document.getElementById('statusTitle');
    elements.statusDetail = document.getElementById('statusDetail');
    elements.riskLevel = document.getElementById('riskLevel');
    elements.detectedDomainField = document.getElementById('detectedDomainField');
    elements.impersonatedBrandItem = document.getElementById('impersonatedBrandItem');
    elements.impersonatedBrandField = document.getElementById('impersonatedBrandField');
    elements.checksHeading = document.getElementById('checksHeading');
    elements.checksList = document.getElementById('checksList');
    elements.recBody = document.getElementById('recBody');
    elements.actionSection = document.getElementById('actionSection');
    elements.panelBody = document.getElementById('panelBody');
    elements.confirmationView = document.getElementById('confirmationView');
    elements.scannerView = document.getElementById('scannerView');
    elements.scannerUrlInput = document.getElementById('scannerUrlInput');
    elements.btnBackToSafety = document.getElementById('btnBackToSafety');
    elements.btnDismissAnyway = document.getElementById('btnDismissAnyway');
    elements.btnStatePhishing = document.getElementById('btnStatePhishing');
    elements.btnStateSafe = document.getElementById('btnStateSafe');
    elements.avoidBtn = document.getElementById('avoidBtn');
    elements.closeBtn = document.getElementById('closeBtn');
    elements.settingsIcon = document.getElementById('settingsIcon');
    elements.openScannerBtn = document.getElementById('openScannerBtn');
  }

  function playVideo(videoEl) {
    const transitions = getTransitions();
    if (transitions) {
      transitions.playVideo(videoEl);
      return;
    }
    if (!videoEl) return;
    videoEl.muted = true;
    videoEl.defaultMuted = true;
    const playPromise = videoEl.play();
    if (playPromise !== undefined) {
      playPromise.catch(function () {
        // Autoplay restriction handled silently
      });
    }
  }

  function switchVideo(videoEl, newSrc) {
    if (!videoEl) return;
    // Dual preloaded video layers crossfade smoothly in CSS without calling .load()
    if (elements.bgVideoSafe && (videoEl === elements.bgVideo || videoEl === elements.panelBgVideo)) {
      playVideo(videoEl);
      playVideo(videoEl === elements.bgVideo ? elements.bgVideoSafe : elements.panelBgVideoSafe);
      return;
    }
    const currentSrc = videoEl.getAttribute('src') || '';
    if (currentSrc !== newSrc) {
      videoEl.setAttribute('src', newSrc);
      const sourceEl = videoEl.querySelector('source');
      if (sourceEl) {
        sourceEl.setAttribute('src', newSrc);
      }
      videoEl.load();
      playVideo(videoEl);
    } else {
      playVideo(videoEl);
    }
  }

  function removeExistingAlertBanner() {
    if (!elements.panel) return;
    const existing = elements.panel.querySelectorAll('.safety-alert-banner');
    existing.forEach(function (node) {
      node.remove();
    });
  }

  function renderCheckItems(checks) {
    if (!elements.checksList) return;
    elements.checksList.textContent = '';

    const items = Array.isArray(checks) ? checks : [];
    items.forEach(function (item) {
      const itemType = item.type === 'danger' ? 'danger' : 'passed';

      const li = document.createElement('li');
      li.className = `check-item check-item-${itemType}`;

      const leftDiv = document.createElement('div');
      leftDiv.className = 'check-left';
      leftDiv.innerHTML = itemType === 'danger' ? ICONS.checkDanger : ICONS.checkPassed;

      const nameSpan = document.createElement('span');
      nameSpan.className = 'check-name';
      nameSpan.textContent = item.name || '';
      leftDiv.appendChild(nameSpan);

      const statusSpan = document.createElement('span');
      statusSpan.className = `check-status status-badge-${itemType}`;
      statusSpan.textContent = item.status || (itemType === 'danger' ? 'Flagged' : 'Passed');

      li.appendChild(leftDiv);
      li.appendChild(statusSpan);
      elements.checksList.appendChild(li);
    });
  }

  const VALID_OUTCOMES = new Set(['SAFE', 'SUSPICIOUS', 'PHISHING', 'UNVERIFIED']);

  function isExemptInterfaceResult(result) {
    return Boolean(
      result &&
        typeof result === 'object' &&
        (result.exempt ||
          result.isInternalBrowserPage ||
          result.classification === 'EXEMPT' ||
          result.outcome === 'EXEMPT')
    );
  }

  function extractInterfaceClassification(result) {
    if (!result || typeof result !== 'object') {
      return 'UNVERIFIED';
    }
    if (isExemptInterfaceResult(result)) {
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

  function resolveInterfaceState(result) {
    const outcome = extractInterfaceClassification(result);
    if (outcome === 'SAFE') {
      return STATES.SAFE;
    }
    if (outcome === 'EXEMPT') {
      return STATES.NEUTRAL;
    }
    return STATES.PHISHING;
  }

  function buildInvalidWarningResult(reason) {
    return {
      supported: false,
      valid: false,
      verificationFailed: true,
      url: activeTargetUrl || '',
      displayUrl: activeTargetUrl || 'Unverified URL',
      detectedDomain: '—',
      impersonatedBrand: null,
      uiState: STATES.PHISHING,
      outcome: 'UNVERIFIED',
      classification: 'UNVERIFIED',
      riskLevel: 'Unverified',
      riskBadge: 'UNVERIFIED',
      headerSubtitle: '⚠️ Caution: Verification Failed',
      statusTitle: 'Unable to Verify URL',
      statusDetail:
        reason ||
        'URL verification could not be completed due to a technical failure or insufficient analysis data. PhishGuard cannot confirm whether this site is safe or phishing.',
      checksHeading: 'Verification details',
      checks: [
        { name: 'URL verification', status: 'Failed', type: 'passed' },
        { name: 'Confirmed phishing indicators', status: 'None confirmed', type: 'passed' },
      ],
      recommendation:
        'Verification failed before analysis could complete. Confirm the website destination independently before sharing sensitive details.',
    };
  }

  function getToneForResult(result) {
    const outcome = extractInterfaceClassification(result);
    if (outcome === 'SAFE') return 'safe';
    if (outcome === 'EXEMPT') return 'neutral';
    if (outcome === 'SUSPICIOUS' || outcome === 'UNVERIFIED') return 'suspicious';
    return 'phishing';
  }

  function setChromeFooterAndControls(mode, animateControls) {
    const transitions = getTransitions();
    const isScanner = mode === 'scanner';

    if (elements.statusHeaderControls) {
      elements.statusHeaderControls.style.display = isScanner ? 'none' : 'flex';
      if (!isScanner && animateControls && transitions) {
        transitions.pulseElement(elements.statusHeaderControls, 'controls-entering');
      }
    }
    if (elements.scannerHeaderControls) {
      elements.scannerHeaderControls.style.display = isScanner ? 'flex' : 'none';
      if (isScanner && animateControls && transitions) {
        transitions.pulseElement(elements.scannerHeaderControls, 'controls-entering');
      }
    }
    if (elements.panelFooterText) {
      elements.panelFooterText.textContent = isScanner
        ? 'PhishGuard • Manual URL Inspection (No network requests sent to scanned URLs)'
        : 'PhishGuard • URL Security';
    }
  }

  function setToggleButtonState(btnEl, isVisible) {
    if (!btnEl) return;
    if (isVisible) {
      btnEl.hidden = false;
      btnEl.disabled = false;
      if (typeof btnEl.removeAttribute === 'function') {
        btnEl.removeAttribute('hidden');
        btnEl.removeAttribute('disabled');
      }
      if (typeof btnEl.setAttribute === 'function') {
        btnEl.setAttribute('aria-hidden', 'false');
      }
      btnEl.tabIndex = 0;
      if (btnEl.style) btnEl.style.display = 'inline-flex';
      if (btnEl.classList) btnEl.classList.add('active');
    } else {
      btnEl.hidden = true;
      btnEl.disabled = true;
      if (typeof btnEl.setAttribute === 'function') {
        btnEl.setAttribute('hidden', '');
        btnEl.setAttribute('disabled', '');
        btnEl.setAttribute('aria-hidden', 'true');
      }
      btnEl.tabIndex = -1;
      if (btnEl.style) btnEl.style.display = 'none';
      if (btnEl.classList) btnEl.classList.remove('active');
    }
  }

  function syncStateToggleButtons(resultOrClass, resolvedUiState) {
    const resolvedState =
      resolvedUiState !== undefined
        ? resolvedUiState
        : resultOrClass === 'SAFE' || resultOrClass === 'Safe'
          ? STATES.SAFE
          : resultOrClass === 'EXEMPT'
            ? STATES.NEUTRAL
            : resultOrClass && typeof resultOrClass === 'object'
              ? resolveInterfaceState(resultOrClass)
              : STATES.PHISHING;

    if (resolvedState === STATES.NEUTRAL) {
      setToggleButtonState(elements.btnStatePhishing, false);
      setToggleButtonState(elements.btnStateSafe, false);
      return;
    }

    const isSafe = resolvedState === STATES.SAFE;
    setToggleButtonState(elements.btnStatePhishing, !isSafe);
    setToggleButtonState(elements.btnStateSafe, isSafe);
  }

  function writeStatusDom(inputResult, opts) {
    const result =
      inputResult && typeof inputResult === 'object' ? inputResult : buildInvalidWarningResult();
    const outcome = extractInterfaceClassification(result);
    const targetState =
      outcome === 'SAFE' ? STATES.SAFE : outcome === 'EXEMPT' ? STATES.NEUTRAL : STATES.PHISHING;
    const theme = STATE_THEME[targetState];
    const isMedium =
      targetState === STATES.PHISHING && (outcome === 'SUSPICIOUS' || outcome === 'UNVERIFIED');
    const nextTone = getToneForResult(result);
    const toneChanged = nextTone !== lastThemeTone;
    const prevSubtitle = elements.headerSubtitle ? elements.headerSubtitle.textContent : '';

    currentState = targetState;
    isDismissedForTab = Boolean(opts && opts.dismissed);

    // 1. Document title
    if (outcome === 'EXEMPT') {
      document.title = theme.pageTitle;
    } else if (outcome === 'UNVERIFIED') {
      document.title = 'PhishGuard – Verification Failed';
    } else if (targetState === STATES.PHISHING && outcome === 'SUSPICIOUS') {
      document.title = 'PhishGuard – Suspicious URL';
    } else {
      document.title = theme.pageTitle;
    }

    // 2. State classes on body, panel, and mutually exclusive Safe/Phishing indicator buttons
    if (targetState === STATES.NEUTRAL) {
      if (elements.body && elements.body.classList) {
        elements.body.classList.add('state-neutral');
        elements.body.classList.remove('state-safe', 'state-phishing', 'state-medium');
      }
      if (elements.panel && elements.panel.classList) {
        elements.panel.classList.add('state-neutral');
        elements.panel.classList.remove('state-safe', 'state-phishing', 'state-medium');
      }
    } else if (targetState === STATES.PHISHING) {
      if (elements.body && elements.body.classList) {
        elements.body.classList.remove('state-neutral');
        elements.body.classList.add('state-phishing');
        elements.body.classList.remove('state-safe');
        elements.body.classList.toggle('state-medium', isMedium);
      }
      if (elements.panel && elements.panel.classList) {
        elements.panel.classList.remove('state-neutral');
        elements.panel.classList.add('state-phishing');
        elements.panel.classList.remove('state-safe');
        elements.panel.classList.toggle('state-medium', isMedium);
      }
    } else {
      if (elements.body && elements.body.classList) {
        elements.body.classList.add('state-safe');
        elements.body.classList.remove('state-neutral', 'state-phishing', 'state-medium');
      }
      if (elements.panel && elements.panel.classList) {
        elements.panel.classList.add('state-safe');
        elements.panel.classList.remove('state-neutral', 'state-phishing', 'state-medium');
      }
    }
    syncStateToggleButtons(result, targetState);

    if (opts && opts.animateAccent && toneChanged && getTransitions()) {
      getTransitions().triggerAccentWash(elements.panelAccentWash, nextTone);
    }
    lastThemeTone = nextTone;

    // 3. Background videos (crossfaded cleanly without flicker)
    if (theme.bgVideoSrc && theme.panelBgVideoSrc) {
      switchVideo(elements.bgVideo, theme.bgVideoSrc);
      switchVideo(elements.panelBgVideo, theme.panelBgVideoSrc);
    }

    // 4. Header subtitle
    const nextSubtitle =
      result.headerSubtitle ||
      (targetState === STATES.SAFE
        ? 'URL Security Extension'
        : outcome === 'EXEMPT'
          ? 'Exempt Page • Not Scanned'
          : outcome === 'UNVERIFIED'
            ? '⚠️ Caution: Verification Failed'
            : '⚠️ Caution: Suspicious URL Patterns');
    if (elements.headerSubtitle) {
      elements.headerSubtitle.textContent = nextSubtitle;
      if (opts && opts.animateHeader && nextSubtitle !== prevSubtitle && getTransitions()) {
        getTransitions().pulseElement(elements.headerSubtitle, 'subtitle-entering');
      }
    }

    // 5. Current website URL
    const displayUrl = result.displayUrl || result.url || 'Unavailable';
    if (elements.urlField) {
      elements.urlField.textContent = displayUrl;
      elements.urlField.setAttribute('title', displayUrl);
    }

    // 6. Status section
    if (elements.statusSection) {
      elements.statusSection.className = `status-card ${theme.statusClass}`;
    }
    if (elements.statusIconWrapper) {
      const iconSelector =
        targetState === STATES.SAFE
          ? '.status-icon-safe'
          : targetState === STATES.NEUTRAL
            ? '.status-icon-neutral'
            : '.status-icon-warning';
      const hasMatchingIcon =
        typeof elements.statusIconWrapper.querySelector === 'function' &&
        Boolean(elements.statusIconWrapper.querySelector(iconSelector));
      if (!(opts && opts.preserveStatusIcon && hasMatchingIcon)) {
        elements.statusIconWrapper.innerHTML = theme.statusIcon;
      }
    }
    if (elements.statusTitle) {
      elements.statusTitle.textContent =
        result.statusTitle ||
        (targetState === STATES.SAFE
          ? 'Website Appears Safe'
          : outcome === 'EXEMPT'
            ? 'Exempt Page (Not Scanned)'
            : outcome === 'UNVERIFIED'
              ? 'Unable to Verify URL'
              : 'Suspicious URL Detected');
    }
    if (elements.statusDetail) {
      elements.statusDetail.textContent =
        result.statusDetail ||
        (targetState === STATES.SAFE
          ? 'Analysis completed cleanly with no meaningful phishing indicators detected.'
          : outcome === 'EXEMPT'
            ? 'This internal browser, extension, or local file URL is exempt from website phishing scanning.'
            : outcome === 'UNVERIFIED'
              ? 'URL verification failed due to a technical failure or insufficient analysis data. PhishGuard cannot confirm whether this site is safe or phishing.'
              : 'Meaningful suspicious indicators were detected.');
    }

    // 7. Qualitative Risk Classification & Domain Metadata (no numerical scores)
    if (elements.riskLevel) {
      elements.riskLevel.className = 'risk-badge';
      if (outcome === 'SAFE') {
        elements.riskLevel.textContent = result.riskBadge || 'SAFE';
        elements.riskLevel.classList.add('risk-badge-low');
      } else if (outcome === 'EXEMPT' || result.isInternalBrowserPage) {
        elements.riskLevel.textContent = result.riskBadge || 'EXEMPT';
        elements.riskLevel.classList.add('risk-badge-neutral');
      } else if (outcome === 'PHISHING') {
        elements.riskLevel.textContent = result.riskBadge || 'HIGH RISK';
        elements.riskLevel.classList.add('risk-badge-high');
      } else if (outcome === 'SUSPICIOUS') {
        elements.riskLevel.textContent = result.riskBadge || 'SUSPICIOUS';
        elements.riskLevel.classList.add('risk-badge-medium');
      } else {
        elements.riskLevel.textContent = result.riskBadge || 'UNVERIFIED';
        elements.riskLevel.classList.add('risk-badge-neutral');
      }
    }

    if (elements.detectedDomainField) {
      const dom = result.detectedDomain || result.hostname || result.domain || '—';
      elements.detectedDomainField.textContent = dom;
      elements.detectedDomainField.setAttribute('title', dom);
    }

    if (elements.impersonatedBrandItem && elements.impersonatedBrandField) {
      if (result.impersonatedBrand && result.impersonatedBrand.name) {
        const b = result.impersonatedBrand;
        elements.impersonatedBrandField.textContent = `${b.name} (${b.canonicalDomain})`;
        elements.impersonatedBrandItem.style.display = 'flex';
      } else {
        elements.impersonatedBrandField.textContent = '—';
        elements.impersonatedBrandItem.style.display = 'none';
      }
    }

    // 8. Checks / Reasons
    if (elements.checksHeading) {
      elements.checksHeading.textContent =
        result.checksHeading ||
        (targetState === STATES.SAFE
          ? 'Security checks'
          : targetState === STATES.NEUTRAL
            ? 'Verification details'
            : 'Detected reasons');
    }
    renderCheckItems(result.checks);

    // 9. Recommendation
    if (elements.recBody) {
      elements.recBody.textContent = result.recommendation || '';
    }

    // 10. Actions visibility
    if (elements.actionSection) {
      elements.actionSection.style.display = theme.showActions ? 'flex' : 'none';
    }

    // 11. If warning was already dismissed for this tab (opened via popup), show re-enable option
    if (isDismissedForTab && targetState === STATES.PHISHING) {
      showDismissedBanner();
    }
  }

  function applyDetectionResult(result, options) {
    const resolvedResult =
      result && typeof result === 'object' ? result : buildInvalidWarningResult();
    const opts = options || {};
    currentDetectionResult = resolvedResult;

    const targetState = resolveInterfaceState(resolvedResult);
    const clsSignature = extractInterfaceClassification(resolvedResult) || 'invalid';
    const nextSignature = [
      clsSignature,
      targetState,
      resolvedResult.displayUrl || resolvedResult.url || '',
      Boolean(opts.dismissed),
    ].join('::');

    // Update cached tab data without disrupting user while inspecting a URL manually
    if (activeInterface === 'scanner' && !opts.exitScanner) {
      return;
    }

    const comingFromOtherView = activeInterface !== 'status';
    const shouldPreserveIcon =
      !comingFromOtherView &&
      !opts.forceTransition &&
      !opts.forceIconReplay &&
      hasHydratedInitialState &&
      nextSignature === lastVisualSignature;
    const shouldAnimate =
      !opts.skipTransition &&
      (comingFromOtherView ||
        (hasHydratedInitialState && (opts.forceTransition || nextSignature !== lastVisualSignature)));

    const fromView =
      activeInterface === 'scanner'
        ? elements.scannerView
        : activeInterface === 'confirmation'
          ? elements.confirmationView
          : elements.panelBody;

    const transitions = getTransitions();
    if (transitions && elements.panelStage && elements.panelBody) {
      transitions.switchStageView({
        stageEl: elements.panelStage,
        fromView: fromView,
        toView: elements.panelBody,
        cloneFrom: fromView === elements.panelBody,
        skipAnimation: !shouldAnimate,
        onBeforeSwap: function () {
          removeExistingAlertBanner();
          setChromeFooterAndControls('status', comingFromOtherView);
          activeInterface = 'status';
          writeStatusDom(resolvedResult, {
            dismissed: opts.dismissed,
            animateAccent: shouldAnimate,
            animateHeader: shouldAnimate,
            preserveStatusIcon: shouldPreserveIcon,
          });
        },
      });
    } else {
      removeExistingAlertBanner();
      if (elements.confirmationView) elements.confirmationView.style.display = 'none';
      if (elements.scannerView) elements.scannerView.style.display = 'none';
      if (elements.panelBody) elements.panelBody.style.display = 'flex';
      setChromeFooterAndControls('status', false);
      activeInterface = 'status';
      writeStatusDom(resolvedResult, {
        dismissed: opts.dismissed,
        preserveStatusIcon: shouldPreserveIcon,
      });
    }

    hasHydratedInitialState = true;
    lastVisualSignature = nextSignature;
    if (document.documentElement && document.documentElement.classList) {
      document.documentElement.classList.remove('pg-hydrating');
    }
    if (elements.body && elements.body.classList && elements.body.classList.contains('pg-booting')) {
      const clearBooting = function () {
        if (elements.body && elements.body.classList) {
          elements.body.classList.remove('pg-booting');
        }
      };
      if (typeof window.requestAnimationFrame === 'function') {
        window.requestAnimationFrame(function () {
          window.requestAnimationFrame(clearBooting);
        });
      } else {
        setTimeout(clearBooting, 20);
      }
    }
  }

  function setState(state, customUrl) {
    if (state !== STATES.SAFE && state !== STATES.PHISHING) return;
    const targetUrl = customUrl || DEFAULT_PREVIEW_URLS[state];
    if (window.PhishGuardDetector) {
      const evaluated = window.PhishGuardDetector.analyzeUrl(targetUrl);
      applyDetectionResult(evaluated, { exitScanner: true });
    }
  }

  function showLoadingPlaceholder() {
    removeExistingAlertBanner();
    activeInterface = 'status';
    currentState = STATES.NEUTRAL;
    setChromeFooterAndControls('status', false);
    if (elements.body && elements.body.classList) {
      elements.body.classList.add('state-neutral');
      elements.body.classList.remove('state-phishing', 'state-safe', 'state-medium');
    }
    if (elements.panel && elements.panel.classList) {
      elements.panel.classList.add('state-neutral');
      elements.panel.classList.remove('state-phishing', 'state-safe', 'state-medium');
    }
    if (elements.confirmationView) {
      elements.confirmationView.style.display = 'none';
      elements.confirmationView.setAttribute('aria-hidden', 'true');
    }
    if (elements.scannerView) {
      elements.scannerView.style.display = 'none';
      elements.scannerView.setAttribute('aria-hidden', 'true');
    }
    if (elements.panelBody) {
      elements.panelBody.style.display = 'flex';
      elements.panelBody.setAttribute('aria-hidden', 'false');
    }
    if (elements.headerSubtitle) {
      elements.headerSubtitle.textContent = 'Analyzing current website...';
    }
    if (elements.urlField) {
      elements.urlField.textContent = 'Checking active tab URL...';
      elements.urlField.setAttribute('title', '');
    }
    if (elements.statusSection) {
      elements.statusSection.className = 'status-card status-neutral';
    }
    if (elements.statusIconWrapper) {
      elements.statusIconWrapper.innerHTML = ICONS.statusNeutral;
    }
    if (elements.statusTitle) {
      elements.statusTitle.textContent = 'Checking Website Security';
    }
    if (elements.statusDetail) {
      elements.statusDetail.textContent = 'Evaluating URL structure and risk indicators...';
    }
    if (elements.riskLevel) {
      elements.riskLevel.className = 'risk-badge risk-badge-neutral';
      elements.riskLevel.textContent = 'CHECKING';
    }
    if (elements.detectedDomainField) {
      elements.detectedDomainField.textContent = '—';
    }
    if (elements.impersonatedBrandItem) {
      elements.impersonatedBrandItem.style.display = 'none';
    }
    if (elements.checksHeading) {
      elements.checksHeading.textContent = 'Security checks';
    }
    if (elements.checksList) {
      elements.checksList.textContent = '';
    }
    if (elements.recBody) {
      elements.recBody.textContent = 'Inspecting current destination before displaying classification details.';
    }
    if (elements.actionSection) {
      elements.actionSection.style.display = 'none';
    }
    setToggleButtonState(elements.btnStatePhishing, false);
    setToggleButtonState(elements.btnStateSafe, false);
  }

  function showConfirmation() {
    if (!elements.confirmationView || !elements.panelBody) return;
    if (activeInterface === 'confirmation') return;

    const fromView = activeInterface === 'scanner' ? elements.scannerView : elements.panelBody;
    const transitions = getTransitions();
    if (transitions && elements.panelStage) {
      transitions.switchStageView({
        stageEl: elements.panelStage,
        fromView: fromView,
        toView: elements.confirmationView,
        cloneFrom: false,
        onBeforeSwap: function () {
          activeInterface = 'confirmation';
          setChromeFooterAndControls('confirmation', false);
          if (elements.headerSubtitle) {
            elements.headerSubtitle.textContent = '⚠️ Confirm: Dismiss Security Warning';
            transitions.pulseElement(elements.headerSubtitle, 'subtitle-entering');
          }
        },
      });
    } else {
      elements.panelBody.style.display = 'none';
      elements.confirmationView.style.display = 'flex';
      elements.confirmationView.setAttribute('aria-hidden', 'false');
      activeInterface = 'confirmation';
      if (elements.headerSubtitle) {
        elements.headerSubtitle.textContent = '⚠️ Confirm: Dismiss Security Warning';
      }
    }
  }

  function hideConfirmation() {
    if (!elements.confirmationView || !elements.panelBody) return;
    if (activeInterface !== 'confirmation') {
      elements.confirmationView.style.display = 'none';
      elements.confirmationView.setAttribute('aria-hidden', 'true');
      return;
    }

    const transitions = getTransitions();
    if (transitions && elements.panelStage) {
      transitions.switchStageView({
        stageEl: elements.panelStage,
        fromView: elements.confirmationView,
        toView: elements.panelBody,
        cloneFrom: false,
        onBeforeSwap: function () {
          activeInterface = 'status';
          setChromeFooterAndControls('status', false);
          if (elements.headerSubtitle && currentDetectionResult) {
            elements.headerSubtitle.textContent = currentDetectionResult.headerSubtitle || '';
            transitions.pulseElement(elements.headerSubtitle, 'subtitle-entering');
          }
        },
      });
    } else {
      elements.confirmationView.style.display = 'none';
      elements.confirmationView.setAttribute('aria-hidden', 'true');
      elements.panelBody.style.display = 'flex';
      activeInterface = 'status';
      if (elements.headerSubtitle && currentDetectionResult) {
        elements.headerSubtitle.textContent = currentDetectionResult.headerSubtitle || '';
      }
    }
  }

  function openScanner() {
    if (!elements.scannerView || !elements.panelStage) {
      const target = isExtensionRuntime() ? './scanner.html?from=popup' : './scanner.html';
      window.location.href = target;
      return;
    }
    if (activeInterface === 'scanner') {
      if (elements.scannerUrlInput) elements.scannerUrlInput.focus();
      return;
    }

    const fromView = activeInterface === 'confirmation' ? elements.confirmationView : elements.panelBody;
    const transitions = getTransitions();

    const applyScannerActivation = function () {
      removeExistingAlertBanner();
      activeInterface = 'scanner';
      setChromeFooterAndControls('scanner', true);
      document.title = 'PhishGuard – Check a URL';
      if (window.PhishGuardScanner && typeof window.PhishGuardScanner.onActivated === 'function') {
        window.PhishGuardScanner.onActivated(lastThemeTone);
      }
      if (document.documentElement && document.documentElement.classList) {
        document.documentElement.classList.remove('pg-hydrating');
      }
    };

    if (transitions) {
      transitions.switchStageView({
        stageEl: elements.panelStage,
        fromView: fromView,
        toView: elements.scannerView,
        cloneFrom: false,
        onBeforeSwap: applyScannerActivation,
      });
    } else {
      if (fromView) fromView.style.display = 'none';
      applyScannerActivation();
      elements.scannerView.style.display = 'flex';
      elements.scannerView.setAttribute('aria-hidden', 'false');
    }

    if (elements.scannerUrlInput) {
      elements.scannerUrlInput.focus();
    }
  }

  function openTabStatus() {
    if (activeInterface !== 'scanner') return;
    if (currentDetectionResult) {
      applyDetectionResult(currentDetectionResult, {
        dismissed: isDismissedForTab,
        exitScanner: true,
        forceTransition: true,
      });
      return;
    }
    if (window.PhishGuardDetector) {
      applyDetectionResult(
        window.PhishGuardDetector.analyzeUrl(DEFAULT_PREVIEW_URLS[currentState] || ''),
        { exitScanner: true, forceTransition: true }
      );
    }
  }

  function syncThemeTone(tone) {
    lastThemeTone =
      tone === 'phishing'
        ? 'phishing'
        : tone === 'suspicious'
          ? 'suspicious'
          : tone === 'neutral'
            ? 'neutral'
            : 'safe';
  }

  function showNavigatingBanner() {
    removeExistingAlertBanner();
    const alertBox = document.createElement('div');
    alertBox.className = 'safety-alert-banner';
    alertBox.innerHTML = `
      <div class="alert-content">
        <strong>Navigating away to safety...</strong>
        <span>Closing unsafe page. Stay protected with PhishGuard.</span>
      </div>
    `;
    elements.panel.appendChild(alertBox);
    return alertBox;
  }

  function showDismissedBanner() {
    removeExistingAlertBanner();
    const alertBox = document.createElement('div');
    alertBox.className = 'safety-alert-banner';
    alertBox.innerHTML = `
      <div class="alert-content">
        <strong>Warning Dismissed</strong>
        <span>You have chosen to dismiss this warning. The website remains unverified and high risk.</span>
        <button type="button" class="confirm-btn back-safety-btn" id="btnRecheck" style="margin-top: 8px; align-self: center;">
          Re-enable Protection
        </button>
      </div>
    `;
    elements.panel.appendChild(alertBox);

    const recheckBtn = alertBox.querySelector('#btnRecheck');
    if (recheckBtn) {
      recheckBtn.addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();

        if (isExtensionRuntime() && activeTabId !== null && activeTargetUrl) {
          sendRuntimeMessage({
            type: 'PHISHGUARD_REENABLE_PROTECTION',
            tabId: activeTabId,
            url: activeTargetUrl,
          }).then(function () {
            alertBox.remove();
            isDismissedForTab = false;
            hideConfirmation();
            if (!isWarningPageMode) {
              if (chrome.tabs && chrome.tabs.update && typeof activeTabId === 'number') {
                try {
                  chrome.tabs.update(activeTabId, { active: true });
                } catch (_) {
                  // Ignore if tab closed
                }
              }
              window.close();
            }
          });
          return;
        }

        alertBox.remove();
        hideConfirmation();
      });
    }
  }

  function sendRuntimeMessage(payload) {
    return new Promise(function (resolve) {
      if (!isExtensionRuntime()) {
        resolve(null);
        return;
      }
      try {
        chrome.runtime.sendMessage(payload, function (response) {
          if (chrome.runtime.lastError) {
            resolve(null);
            return;
          }
          resolve(response || null);
        });
      } catch (_) {
        resolve(null);
      }
    });
  }

  function handleBackToSafety(e) {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }

    const banner = showNavigatingBanner();

    if (isExtensionRuntime() && activeTabId !== null) {
      sendRuntimeMessage({
        type: 'PHISHGUARD_BACK_TO_SAFETY',
        tabId: activeTabId,
        url: activeTargetUrl,
      }).then(function () {
        if (!isWarningPageMode) {
          if (chrome.tabs && chrome.tabs.update && typeof activeTabId === 'number') {
            try {
              chrome.tabs.update(activeTabId, { active: true });
            } catch (_) {
              // Ignore if tab closed
            }
          }
          setTimeout(function () {
            window.close();
          }, 350);
        }
      });
      return;
    }

    setTimeout(function () {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        banner.remove();
      }
    }, 900);
  }

  function handleDismissAnyway(e) {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }

    if (isExtensionRuntime() && activeTabId !== null && activeTargetUrl) {
      sendRuntimeMessage({
        type: 'PHISHGUARD_DISMISS_WARNING',
        tabId: activeTabId,
        url: activeTargetUrl,
      }).then(function (resp) {
        if (resp && resp.redirected && isWarningPageMode) {
          return;
        }
        isDismissedForTab = true;
        showDismissedBanner();
      });
      return;
    }

    showDismissedBanner();
  }

  function queryActiveTab() {
    return new Promise(function (resolve) {
      if (!isExtensionRuntime() || !chrome.tabs || !chrome.tabs.query) {
        resolve(null);
        return;
      }
      chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (chrome.runtime.lastError || !tabs || !tabs.length) {
          resolve(null);
          return;
        }
        resolve(tabs[0]);
      });
    });
  }

  function getTabById(tabId) {
    return new Promise(function (resolve) {
      if (!isExtensionRuntime() || typeof tabId !== 'number' || !chrome.tabs || !chrome.tabs.get) {
        resolve(null);
        return;
      }
      try {
        chrome.tabs.get(tabId, function (tab) {
          if (chrome.runtime.lastError || !tab) {
            resolve(null);
            return;
          }
          resolve(tab);
        });
      } catch (_) {
        resolve(null);
      }
    });
  }

  function isOwnExtensionUrl(urlStr) {
    if (!urlStr || !isExtensionRuntime() || !chrome.runtime.getURL) return false;
    const extRoot = chrome.runtime.getURL('');
    return (
      (extRoot && urlStr.startsWith(extRoot)) ||
      urlStr.startsWith(chrome.runtime.getURL('index.html')) ||
      urlStr.startsWith(chrome.runtime.getURL('scanner.html'))
    );
  }

  function extractWarningParamsFromUrl(urlStr) {
    try {
      const parsed = new URL(urlStr);
      const rawTab = parsed.searchParams.get('tabId') ?? parsed.searchParams.get('targetTabId');
      return {
        mode: parsed.searchParams.get('mode') || '',
        url: parsed.searchParams.get('url') || parsed.searchParams.get('targetUrl') || '',
        tabId: rawTab !== null && rawTab !== '' && !Number.isNaN(Number(rawTab)) ? Number(rawTab) : null,
      };
    } catch (_) {
      return { mode: '', url: '', tabId: null };
    }
  }

  async function syncStatusForTab(tabId, rawUrl, options) {
    const opts = options || {};
    const warningPrefix = chrome.runtime.getURL('index.html');
    let lookupTabId = tabId;
    let lookupUrl = rawUrl || '';
    let isFromWarningUrl = false;

    if (lookupUrl.startsWith(warningPrefix)) {
      const warningMeta = extractWarningParamsFromUrl(lookupUrl);
      if (warningMeta.mode === 'warning') {
        isFromWarningUrl = true;
      }
      if (warningMeta.url) {
        lookupUrl = warningMeta.url;
      }
      if (warningMeta.tabId !== null) {
        lookupTabId = warningMeta.tabId;
      }
    }

    if (isOwnExtensionUrl(lookupUrl)) {
      lookupUrl = '';
    }

    activeTabId = typeof lookupTabId === 'number' ? lookupTabId : activeTabId;
    activeTargetUrl = lookupUrl;

    const bgResponse = await sendRuntimeMessage({
      type: 'PHISHGUARD_GET_TAB_STATUS',
      tabId: activeTabId,
      url: activeTargetUrl,
      fromWarningPage: isFromWarningUrl,
      fromStatusTab: isFullTabStatusMode,
    });

    if (bgResponse && bgResponse.ok && 'result' in bgResponse) {
      const resolvedBgResult = bgResponse.result;
      activeTargetUrl = (resolvedBgResult && resolvedBgResult.url) || activeTargetUrl;
      applyDetectionResult(resolvedBgResult, {
        dismissed: bgResponse.dismissed,
        skipTransition: opts.skipTransition !== undefined ? opts.skipTransition : !hasHydratedInitialState,
        exitScanner: Boolean(opts.exitScanner),
        forceTransition: Boolean(opts.forceTransition),
      });
      if (isPopupMode && resolvedBgResult && resolvedBgResult.blocked && typeof window.close === 'function') {
        window.close();
      }
      return;
    }

    const fallbackResult = window.PhishGuardDetector
      ? window.PhishGuardDetector.analyzeUrl(activeTargetUrl)
      : buildInvalidWarningResult();
    applyDetectionResult(fallbackResult, {
      skipTransition: opts.skipTransition !== undefined ? opts.skipTransition : !hasHydratedInitialState,
      exitScanner: Boolean(opts.exitScanner),
      forceTransition: Boolean(opts.forceTransition),
    });
  }

  async function loadExtensionState() {
    const pageParams = new URLSearchParams(window.location.search);
    const paramMode = pageParams.get('mode');
    const paramUrl = pageParams.get('url');
    const paramTabId = pageParams.get('tabId');
    const paramTargetTabId = pageParams.get('targetTabId');
    const paramTargetUrl = pageParams.get('targetUrl');

    isPopupMode = paramMode === 'popup';
    if (isPopupMode && document.documentElement && document.documentElement.classList) {
      document.documentElement.classList.add('pg-popup');
    }

    // Case 0: Dedicated / Opened Manual URL Scanner (?mode=scanner&scanUrl=...)
    if (paramMode === 'scanner') {
      isWarningPageMode = false;
      isFullTabStatusMode = true;
      const passedScanUrl =
        pageParams.get('scanUrl') ||
        pageParams.get('targetUrl') ||
        pageParams.get('url') ||
        pageParams.get('prefill') ||
        '';
      openScanner();
      if (passedScanUrl && window.PhishGuardScanner && typeof window.PhishGuardScanner.loadScannedUrl === 'function') {
        await window.PhishGuardScanner.loadScannedUrl(passedScanUrl, { autoScan: true });
      }
      return;
    }

    // Case 1: Automatic Full-Screen Warning Interstitial (?mode=warning&tabId=...&url=...)
    if (paramMode === 'warning') {
      isWarningPageMode = true;
      isFullTabStatusMode = false;
      activeTargetUrl = paramUrl || '';
      activeTabId = paramTabId !== null && !Number.isNaN(Number(paramTabId)) ? Number(paramTabId) : null;

      // Render synchronously immediately with zero flash of stale/hardcoded UI
      let localClass = '';
      if (paramUrl && window.PhishGuardDetector) {
        const localResult = window.PhishGuardDetector.analyzeUrl(paramUrl);
        localClass = localResult.riskLevel || localResult.classification || '';
        applyDetectionResult(localResult, { skipTransition: true });
      } else {
        applyDetectionResult(buildInvalidWarningResult(), { skipTransition: true });
      }

      if (activeTabId === null) {
        const currentTab = await queryActiveTab();
        if (currentTab && typeof currentTab.id === 'number') {
          activeTabId = currentTab.id;
        }
      }

      const bgResponse = await sendRuntimeMessage({
        type: 'PHISHGUARD_GET_TAB_STATUS',
        tabId: activeTabId,
        url: paramUrl || '',
        fromWarningPage: true,
      });

      if (bgResponse && bgResponse.ok && 'result' in bgResponse) {
        const resolvedBgClass = extractInterfaceClassification(bgResponse.result) || '';
        const changedVerdict =
          resolvedBgClass !== localClass || Boolean(bgResponse.dismissed);
        applyDetectionResult(bgResponse.result, {
          dismissed: bgResponse.dismissed,
          skipTransition: !changedVerdict,
        });
      }
      return;
    }

    // Case 2: Full-Tab Security Status Viewer (?mode=status&targetTabId=...&targetUrl=...)
    if (paramMode === 'status') {
      isFullTabStatusMode = true;
      isWarningPageMode = false;
      const parsedTargetId =
        paramTargetTabId !== null && paramTargetTabId !== '' && !Number.isNaN(Number(paramTargetTabId))
          ? Number(paramTargetTabId)
          : null;
      activeTabId = parsedTargetId;
      activeTargetUrl = paramTargetUrl || '';

      // Render known targetUrl immediately if available so the full-tab UI shows zero flicker
      if (activeTargetUrl && window.PhishGuardDetector) {
        applyDetectionResult(window.PhishGuardDetector.analyzeUrl(activeTargetUrl), {
          skipTransition: !hasHydratedInitialState,
        });
      } else {
        showLoadingPlaceholder();
      }

      // Confirm live URL of target tab in case it updated while opening
      const liveTargetTab = parsedTargetId !== null ? await getTabById(parsedTargetId) : null;
      const resolvedUrl =
        liveTargetTab && liveTargetTab.url && !isOwnExtensionUrl(liveTargetTab.url)
          ? liveTargetTab.url
          : activeTargetUrl;

      await syncStatusForTab(parsedTargetId, resolvedUrl, {
        skipTransition: true,
      });
      return;
    }

    // Case 3: Direct / Fallback Invocation (Popup or direct chrome-extension://.../index.html)
    showLoadingPlaceholder();
    const activeTab = await queryActiveTab();

    if (!activeTab) {
      applyDetectionResult(
        window.PhishGuardDetector ? window.PhishGuardDetector.analyzeUrl('') : buildInvalidWarningResult(),
        { skipTransition: true }
      );
      return;
    }

    // If activeTab is itself our extension tab (e.g. opened directly or from scanner.html),
    // fetch the most recently active website tab from background instead of scanning index.html!
    const activeTabUrl = activeTab.url || activeTab.pendingUrl || '';
    if (isOwnExtensionUrl(activeTabUrl)) {
      if (!isPopupMode) {
        isFullTabStatusMode = true;
      }
      const lastTargetResp = await sendRuntimeMessage({ type: 'PHISHGUARD_GET_LAST_TARGET_TAB' });
      if (lastTargetResp && lastTargetResp.ok && lastTargetResp.targetUrl && !isOwnExtensionUrl(lastTargetResp.targetUrl)) {
        await syncStatusForTab(lastTargetResp.targetTabId, lastTargetResp.targetUrl);
        return;
      }
      applyDetectionResult(
        window.PhishGuardDetector ? window.PhishGuardDetector.analyzeUrl('') : buildInvalidWarningResult(),
        { skipTransition: true }
      );
      return;
    }

    // Immediately analyze and render the active tab's URL synchronously before awaiting background IPC
    // so the popup never flashes a fallback/placeholder frame before displaying the true verdict.
    const tabId = typeof activeTab.id === 'number' ? activeTab.id : null;
    if (activeTabUrl && window.PhishGuardDetector) {
      activeTabId = tabId;
      activeTargetUrl = activeTabUrl;
      applyDetectionResult(window.PhishGuardDetector.analyzeUrl(activeTabUrl), {
        skipTransition: true,
      });
    }

    await syncStatusForTab(
      tabId,
      activeTabUrl
    );
  }

  function loadStandalonePreviewState() {
    const params = new URLSearchParams(window.location.search);
    const paramMode = params.get('mode');
    const paramUrl = params.get('url');
    isPopupMode = paramMode === 'popup';
    if (isPopupMode && document.documentElement && document.documentElement.classList) {
      document.documentElement.classList.add('pg-popup');
    }

    const previewUrl = paramUrl || DEFAULT_PREVIEW_URLS[STATES.PHISHING];
    if (window.PhishGuardDetector) {
      activeTargetUrl = paramUrl || '';
      applyDetectionResult(window.PhishGuardDetector.analyzeUrl(previewUrl), {
        skipTransition: true,
      });
    } else {
      applyDetectionResult(buildInvalidWarningResult(), { skipTransition: true });
    }
  }

  function setupEventListeners() {
    const liveExtension = isExtensionRuntime();

    // State indicator buttons: mutually exclusive; hidden button cannot trigger actions
    if (elements.btnStatePhishing) {
      elements.btnStatePhishing.addEventListener('click', function () {
        if (
          liveExtension ||
          elements.btnStatePhishing.disabled ||
          elements.btnStatePhishing.hidden ||
          elements.btnStatePhishing.getAttribute('aria-hidden') === 'true'
        ) {
          return;
        }
        setState(STATES.PHISHING);
      });
    }
    if (elements.btnStateSafe) {
      elements.btnStateSafe.addEventListener('click', function () {
        if (
          liveExtension ||
          elements.btnStateSafe.disabled ||
          elements.btnStateSafe.hidden ||
          elements.btnStateSafe.getAttribute('aria-hidden') === 'true'
        ) {
          return;
        }
        setState(STATES.SAFE);
      });
    }

    // Settings/refresh icon: re-analyze current URL in live mode, or toggle preview in standalone mode
    if (elements.settingsIcon) {
      if (liveExtension) {
        elements.settingsIcon.setAttribute('title', 'Re-scan current website');
        elements.settingsIcon.setAttribute('aria-label', 'Re-scan current website');
      }
      elements.settingsIcon.addEventListener('click', function () {
        if (liveExtension && activeTabId !== null && activeTargetUrl) {
          sendRuntimeMessage({
            type: 'PHISHGUARD_REANALYZE_URL',
            tabId: activeTabId,
            url: activeTargetUrl,
            skipRedirect: isWarningPageMode,
          }).then(function (resp) {
            if (resp && resp.ok && resp.result) {
              applyDetectionResult(resp.result, {
                dismissed: resp.dismissed,
                forceIconReplay: true,
              });
            }
          });
          return;
        }
        const nextState = currentState === STATES.PHISHING ? STATES.SAFE : STATES.PHISHING;
        setState(nextState);
      });
    }

    // Manual URL Scanner access (smooth inline switch without page reload)
    if (elements.openScannerBtn) {
      elements.openScannerBtn.addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        openScanner();
      });
    }

    // Avoid This Website -> Back to safety
    if (elements.avoidBtn) {
      elements.avoidBtn.addEventListener('click', handleBackToSafety);
    }

    // Dismiss button -> confirmation interface
    if (elements.closeBtn) {
      elements.closeBtn.addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        showConfirmation();
      });
    }

    // Confirmation interface: "Go Back to Safety" -> navigate away to safety
    if (elements.btnBackToSafety) {
      elements.btnBackToSafety.addEventListener('click', handleBackToSafety);
    }

    // Confirmation interface: "Dismiss Anyway"
    if (elements.btnDismissAnyway) {
      elements.btnDismissAnyway.addEventListener('click', handleDismissAnyway);
    }

    // Keep Status view synchronized when the watched tab navigates or when toolbar icon re-targets this tab
    if (liveExtension && chrome.tabs && chrome.tabs.onUpdated) {
      chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
        if (isWarningPageMode) return;
        if (tabId === activeTabId && (changeInfo.url || changeInfo.status === 'complete')) {
          const nextUrl = changeInfo.url || (tab && tab.url) || activeTargetUrl;
          if (!isOwnExtensionUrl(nextUrl)) {
            if (isFullTabStatusMode && window.history && typeof window.history.replaceState === 'function') {
              const params = new URLSearchParams();
              params.set('mode', 'status');
              if (typeof tabId === 'number') params.set('targetTabId', String(tabId));
              if (nextUrl) params.set('targetUrl', nextUrl);
              try {
                window.history.replaceState(null, '', `?${params.toString()}`);
              } catch (_) {
                // Ignore history replace restriction
              }
            }
            syncStatusForTab(tabId, nextUrl, { skipTransition: false });
          }
        }
      });
    }

    if (liveExtension && chrome.tabs && chrome.tabs.onActivated) {
      chrome.tabs.onActivated.addListener(async function (activeInfo) {
        if (isWarningPageMode || !activeInfo || typeof activeInfo.tabId !== 'number') return;
        const activatedTab = await getTabById(activeInfo.tabId);
        if (!activatedTab || isOwnExtensionUrl(activatedTab.url || '')) return;
        await syncStatusForTab(activatedTab.id, activatedTab.url || '', { skipTransition: false });
      });
    }

    if (liveExtension && chrome.runtime && chrome.runtime.onMessage && typeof chrome.runtime.onMessage.addListener === 'function') {
      chrome.runtime.onMessage.addListener(function (message, _sender, sendResponse) {
        if (!message || message.type !== 'PHISHGUARD_SYNC_STATUS_TAB') {
          return false;
        }
        if (isWarningPageMode) {
          return false;
        }
        isFullTabStatusMode = true;
        if (message.statusUrl && window.history && typeof window.history.replaceState === 'function') {
          try {
            window.history.replaceState(null, '', message.statusUrl);
          } catch (_) {
            // Ignore history replace restriction
          }
        }
        syncStatusForTab(
          typeof message.targetTabId === 'number' ? message.targetTabId : null,
          message.targetUrl || '',
          { exitScanner: true, forceTransition: true, skipTransition: false }
        );
        sendResponse({ ok: true });
        return false;
      });
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    initElements();
    setupEventListeners();

    if (isExtensionRuntime()) {
      loadExtensionState();
    } else {
      loadStandalonePreviewState();
    }

    const transitions = getTransitions();
    if (transitions) {
      transitions.playAllVideos(document);
    } else {
      playVideo(elements.bgVideo);
      playVideo(elements.panelBgVideo);
    }
  });

  window.PhishGuard = {
    setState: setState,
    applyDetectionResult: applyDetectionResult,
    resolveInterfaceState: resolveInterfaceState,
    extractInterfaceClassification: extractInterfaceClassification,
    openScanner: openScanner,
    openTabStatus: openTabStatus,
    syncThemeTone: syncThemeTone,
    getActiveInterface: function () {
      return activeInterface;
    },
    isWarningMode: function () {
      return isWarningPageMode;
    },
    isPopupMode: function () {
      return isPopupMode;
    },
    isFullTabMode: function () {
      return isFullTabMode();
    },
    analyzeUrl: function (url) {
      return window.PhishGuardDetector ? window.PhishGuardDetector.analyzeUrl(url) : null;
    },
    getState: function () {
      return currentState;
    },
    getLastResult: function () {
      return currentDetectionResult;
    },
    STATES: STATES,
  };
})();
