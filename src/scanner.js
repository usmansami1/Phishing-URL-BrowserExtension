/**
 * PhishGuard - Manual URL Scanner Controller
 * Reuses the shared detection engine and scoring pipeline while strictly
 * inspecting submitted URLs as text strings without network requests or navigation.
 */
(function () {
  'use strict';

  const ICONS = {
    statusDanger: `
      <svg class="status-icon status-icon-warning" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 2L1 21h22L12 2z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        <line x1="12" y1="9" x2="12" y2="13" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>
        <circle cx="12" cy="17" r="1.3" fill="currentColor"/>
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

  const els = {};
  let isEmbeddedMode = false;
  let currentScannerResult = null;
  let currentScannerClassification = 'idle';
  let lastScannedUrl = '';
  let lastScannerSubtitle = 'Manual URL Scanner';

  function getTransitions() {
    return window.PhishGuardTransitions || null;
  }

  function isExtensionRuntime() {
    return typeof chrome !== 'undefined' && Boolean(chrome.runtime && chrome.runtime.id);
  }

  function isScannerActive() {
    if (!isEmbeddedMode) return true;
    if (window.PhishGuard && typeof window.PhishGuard.getActiveInterface === 'function') {
      return window.PhishGuard.getActiveInterface() === 'scanner';
    }
    return true;
  }

  function initElements() {
    els.body = document.body;
    els.panel = document.getElementById('scannerPanel') || document.querySelector('.extension-panel');
    els.panelAccentWash = document.getElementById('panelAccentWash');
    els.outputStage = document.getElementById('scannerOutputStage');
    els.scannerView = document.getElementById('scannerView') || document.querySelector('.scanner-body');
    els.bgVideo = document.getElementById('bgVideo');
    els.bgVideoAlt = document.getElementById('bgVideoPhishing') || document.getElementById('bgVideoSafe');
    els.panelBgVideo = document.getElementById('panelBgVideo');
    els.panelBgVideoAlt = document.getElementById('panelBgVideoPhishing') || document.getElementById('panelBgVideoSafe');
    els.subtitle = document.getElementById('scannerHeaderSubtitle') || document.getElementById('headerSubtitle');
    els.openInTabBtn = document.getElementById('openInTabBtn');
    els.backToTabBtn = document.getElementById('backToTabBtn');
    els.form = document.getElementById('scannerForm');
    els.input = document.getElementById('scannerUrlInput');
    els.scanBtn = document.getElementById('scanUrlBtn');
    els.clearBtn = document.getElementById('clearScannerBtn');
    els.errorBox = document.getElementById('scannerValidationError');
    els.loadingState = document.getElementById('scannerLoadingState');
    els.emptyHint = document.getElementById('scannerEmptyHint');
    els.resultsBox = document.getElementById('scannerResults');
    els.verdictCard = document.getElementById('scannerVerdictCard');
    els.verdictIconWrapper = document.getElementById('scannerStatusIconWrapper');
    els.classificationBadge = document.getElementById('classificationBadge');
    els.verdictTitle = document.getElementById('scannerVerdictTitle');
    els.verdictExplanation = document.getElementById('scannerVerdictExplanation');
    els.detectedUrl = document.getElementById('detectedUrlDisplay');
    els.detectedDomain = document.getElementById('detectedDomainDisplay');
    els.impersonatedBrandRow = document.getElementById('impersonatedBrandRow');
    els.impersonatedBrand = document.getElementById('impersonatedBrandDisplay');
    els.recommendation = document.getElementById('scannerRecommendation');
    els.reasonsHeading = document.getElementById('scannerReasonsHeading');
    els.reasonsList = document.getElementById('reasonsList');
    els.featuresGrid = document.getElementById('suspiciousFeaturesList');
    isEmbeddedMode = Boolean(document.getElementById('scannerView'));
  }

  function ensureElements() {
    if (!els.body && typeof document !== 'undefined' && document.body) {
      initElements();
    }
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
    const p = videoEl.play();
    if (p && typeof p.catch === 'function') {
      p.catch(function () {});
    }
  }

  function switchVideo(videoEl, newSrc) {
    if (!videoEl) return;
    // Dual preloaded video layers crossfade smoothly in CSS without calling .load()
    if (els.bgVideoAlt && (videoEl === els.bgVideo || videoEl === els.panelBgVideo)) {
      playVideo(videoEl);
      playVideo(videoEl === els.bgVideo ? els.bgVideoAlt : els.panelBgVideoAlt);
      return;
    }
    const currentSrc = videoEl.getAttribute('src') || '';
    if (currentSrc !== newSrc) {
      videoEl.setAttribute('src', newSrc);
      const sourceEl = videoEl.querySelector('source');
      if (sourceEl) sourceEl.setAttribute('src', newSrc);
      videoEl.load();
    }
    playVideo(videoEl);
  }

  function getActiveOutputChild() {
    if (els.resultsBox && els.resultsBox.style && els.resultsBox.style.display !== 'none') {
      return els.resultsBox;
    }
    if (els.loadingState && els.loadingState.style && els.loadingState.style.display !== 'none') {
      return els.loadingState;
    }
    if (els.emptyHint && els.emptyHint.style && els.emptyHint.style.display !== 'none') {
      return els.emptyHint;
    }
    return els.emptyHint || els.resultsBox || els.loadingState || null;
  }

  function transitionOutputSection(toView, options) {
    const opts = options || {};
    const displayMode = opts.displayMode || (toView === els.emptyHint ? 'block' : 'flex');
    const transitions = getTransitions();
    const fromView = getActiveOutputChild();

    if (transitions && els.outputStage && toView) {
      transitions.switchStageView({
        stageEl: els.outputStage,
        fromView: fromView,
        toView: toView,
        cloneFrom: fromView === toView,
        displayMode: displayMode,
        skipAnimation: Boolean(opts.skipAnimation),
        onBeforeSwap: opts.onBeforeSwap,
      });
      return;
    }

    if (typeof opts.onBeforeSwap === 'function') {
      opts.onBeforeSwap();
    }
    if (els.loadingState) els.loadingState.style.display = toView === els.loadingState ? displayMode : 'none';
    if (els.emptyHint) els.emptyHint.style.display = toView === els.emptyHint ? displayMode : 'none';
    if (els.resultsBox) els.resultsBox.style.display = toView === els.resultsBox ? displayMode : 'none';
  }

  function isExtensionInternalUrl(rawUrl) {
    const trimmed = String(rawUrl || '').trim().toLowerCase();
    if (!trimmed) return false;
    if (trimmed.startsWith('chrome-extension://')) return true;
    if (isExtensionRuntime() && chrome.runtime && typeof chrome.runtime.getURL === 'function') {
      const extRoot = chrome.runtime.getURL('').toLowerCase();
      if (extRoot && trimmed.startsWith(extRoot)) return true;
    }
    return false;
  }

  function validateUserUrlInput(rawInput) {
    const trimmed = String(rawInput || '').trim();
    if (!trimmed) {
      return { valid: false, error: 'Please enter a URL to check (for example: https://example.com).' };
    }

    if (isExtensionInternalUrl(trimmed)) {
      return {
        valid: false,
        error: 'Cannot scan an internal PhishGuard extension URL. Please enter an external http:// or https:// website URL.',
      };
    }

    if (/\s/.test(trimmed)) {
      return { valid: false, error: 'URL cannot contain spaces. Please check the address and try again.' };
    }

    // Explicitly reject dangerous/internal schemes rather than normalizing them
    const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z\d+\-.]*):/);
    if (schemeMatch) {
      const scheme = schemeMatch[1].toLowerCase();
      if (scheme !== 'http' && scheme !== 'https') {
        return {
          valid: false,
          error: `Unsupported URL scheme "${scheme}:". Manual scanning only evaluates external http:// or https:// web URLs.`,
        };
      }
    }

    const analyzer = window.PhishGuardURLAnalyzer;
    if (!analyzer) {
      return { valid: false, error: 'URL analyzer module is unavailable.' };
    }

    const normalized = analyzer.normalizeUrl(trimmed);
    if (!normalized || !analyzer.isSupportedUrl(normalized.href)) {
      return {
        valid: false,
        error: 'The entered text does not appear to be a valid web URL.',
      };
    }

    // Require either a dot in hostname, localhost, or IPv6 literal when scheme was omitted
    const host = normalized.hostname;
    if (!schemeMatch && host !== 'localhost' && !host.includes('.') && !host.includes(':')) {
      return {
        valid: false,
        error: 'Please enter a complete domain name or URL (for example: suspicious-site.tk/login).',
      };
    }

    return { valid: true, normalizedUrl: normalized.href, rawUrl: trimmed };
  }

  function showValidationError(message) {
    if (!els.errorBox) return;
    els.errorBox.textContent = message;
    els.errorBox.style.display = 'block';
  }

  function clearValidationError() {
    if (!els.errorBox) return;
    els.errorBox.textContent = '';
    els.errorBox.style.display = 'none';
  }

  function setLoading(isLoading) {
    if (els.scanBtn) els.scanBtn.disabled = isLoading;
    if (isLoading) {
      applyVisualTheme('scanning', null, { explicitSubtitle: 'Manual URL Scanner • Scanning...' });
      transitionOutputSection(els.loadingState, { displayMode: 'flex' });
    } else if (els.loadingState) {
      els.loadingState.style.display = 'none';
    }
  }

  function getCurrentPanelTone() {
    if (!els.panel || !els.panel.classList) return 'neutral';
    if (els.panel.classList.contains('state-neutral')) return 'neutral';
    if (els.panel.classList.contains('state-medium')) return 'suspicious';
    if (els.panel.classList.contains('state-phishing')) return 'phishing';
    if (els.panel.classList.contains('state-safe')) return 'safe';
    return 'neutral';
  }

  const VALID_SCANNER_OUTCOMES = new Set(['SAFE', 'SUSPICIOUS', 'PHISHING', 'UNVERIFIED']);

  function resolveScannerClassification(classificationOrResult, explicitResult) {
    const res =
      explicitResult && typeof explicitResult === 'object'
        ? explicitResult
        : classificationOrResult && typeof classificationOrResult === 'object'
          ? classificationOrResult
          : null;
    if (res) {
      if (res.exempt || res.isInternalBrowserPage || res.classification === 'EXEMPT' || res.outcome === 'EXEMPT') {
        return 'EXEMPT';
      }
      const rawOutcome = typeof res.outcome === 'string' ? res.outcome : res.classification;
      if (typeof rawOutcome === 'string' && VALID_SCANNER_OUTCOMES.has(rawOutcome)) {
        return rawOutcome;
      }
      if (res.riskLevel === 'Safe' && (!rawOutcome || rawOutcome === 'Safe' || rawOutcome === 'safe')) return 'SAFE';
      if (res.classification === 'phishing' || res.riskLevel === 'High Risk') return 'PHISHING';
      if (
        res.classification === 'suspicious' ||
        res.riskLevel === 'Suspicious' ||
        res.riskLevel === 'Medium Risk'
      ) {
        return 'SUSPICIOUS';
      }
      return 'UNVERIFIED';
    }
    if (
      classificationOrResult === 'idle' ||
      classificationOrResult === 'scanning' ||
      classificationOrResult === 'neutral'
    ) {
      return classificationOrResult;
    }
    if (typeof classificationOrResult === 'string' && VALID_SCANNER_OUTCOMES.has(classificationOrResult)) {
      return classificationOrResult;
    }
    if (classificationOrResult === 'Safe') return 'SAFE';
    if (classificationOrResult === 'phishing') return 'PHISHING';
    if (classificationOrResult === 'suspicious') return 'SUSPICIOUS';
    if (!classificationOrResult) return 'idle';
    return 'UNVERIFIED';
  }

  function applyVisualTheme(classification, result, options) {
    const opts = options || {};
    const outcome = resolveScannerClassification(classification, result);
    const isIdleOrScanning =
      !result && (outcome === 'idle' || outcome === 'scanning' || outcome === 'neutral');
    const isSafe = !isIdleOrScanning && outcome === 'SAFE';
    const isExempt = !isIdleOrScanning && outcome === 'EXEMPT';
    const isUnverified = !isIdleOrScanning && outcome === 'UNVERIFIED';
    const isNeutral = isIdleOrScanning || isUnverified || isExempt;
    const isMed = !isNeutral && !isSafe && outcome === 'SUSPICIOUS';
    const isPhish = !isNeutral && !isSafe && outcome === 'PHISHING';
    const useWarningTheme = !isNeutral && !isSafe;
    const nextTone = isNeutral ? 'neutral' : isSafe ? 'safe' : isMed ? 'suspicious' : 'phishing';

    currentScannerClassification = outcome;

    let nextSubtitle = 'Manual URL Scanner';
    if (outcome === 'scanning') {
      nextSubtitle = 'Manual URL Scanner • Scanning...';
    } else if (isIdleOrScanning) {
      nextSubtitle = 'Manual URL Scanner';
    } else if (isExempt) {
      nextSubtitle = 'Manual URL Scanner • Exempt Page';
    } else if (isSafe) {
      nextSubtitle = 'Manual URL Scanner • Safe';
    } else if (isPhish) {
      nextSubtitle =
        result && result.isVerifiedMalicious
          ? '⚠️ Manual Scan: Verified Malicious Site'
          : result && result.impersonatedBrand
            ? `⚠️ Manual Scan: Probable ${result.impersonatedBrand.name} Impersonation`
            : '⚠️ Manual Scan: Phishing Indicators Detected';
    } else if (outcome === 'SUSPICIOUS') {
      nextSubtitle = '⚠️ Manual Scan: Suspicious Indicators Detected';
    } else {
      nextSubtitle = '⚠️ Manual Scan: Unable to Verify URL';
    }
    lastScannerSubtitle = opts.explicitSubtitle || nextSubtitle;

    if (!isScannerActive()) {
      return;
    }

    ensureElements();
    const prevTone = opts.previousTone || getCurrentPanelTone();
    const prevSubtitle = els.subtitle ? els.subtitle.textContent : '';

    if (els.body && els.body.classList) {
      els.body.classList.toggle('state-neutral', isNeutral);
      els.body.classList.toggle('state-phishing', useWarningTheme);
      els.body.classList.toggle('state-safe', isSafe);
      els.body.classList.toggle('state-medium', isMed);
    }
    if (els.panel && els.panel.classList) {
      els.panel.classList.toggle('state-neutral', isNeutral);
      els.panel.classList.toggle('state-phishing', useWarningTheme);
      els.panel.classList.toggle('state-safe', isSafe);
      els.panel.classList.toggle('state-medium', isMed);
    }

    if (window.PhishGuard && typeof window.PhishGuard.syncThemeTone === 'function') {
      window.PhishGuard.syncThemeTone(nextTone);
    }

    const transitions = getTransitions();
    if (transitions && els.panelAccentWash && nextTone !== prevTone && !opts.skipAccent) {
      transitions.triggerAccentWash(els.panelAccentWash, nextTone);
    }

    if (isSafe) {
      switchVideo(els.bgVideo, './Citron.mp4');
      switchVideo(els.panelBgVideo, './blend.mp4');
    } else if (useWarningTheme) {
      switchVideo(els.bgVideo, './spam_bg.mp4');
      switchVideo(els.panelBgVideo, './spam_central_bg.mp4');
    }

    if (els.subtitle) {
      els.subtitle.textContent = lastScannerSubtitle;
      if (transitions && lastScannerSubtitle !== prevSubtitle && !opts.skipHeaderPulse) {
        transitions.pulseElement(els.subtitle, 'subtitle-entering');
      }
    }
  }

  function renderReasons(result) {
    if (!els.reasonsList) return;
    els.reasonsList.textContent = '';

    const indicators = Array.isArray(result.indicators) ? result.indicators : [];
    const outcome = resolveScannerClassification(result);
    const isNonAlert = outcome === 'SAFE' || outcome === 'UNVERIFIED' || outcome === 'EXEMPT';
    if (indicators.length > 0) {
      if (els.reasonsHeading) {
        els.reasonsHeading.textContent = isNonAlert
          ? 'Noted signals & security checks'
          : 'Reasons behind classification';
      }
      indicators.forEach(function (ind) {
        const isDanger = !isNonAlert;
        const li = document.createElement('li');
        li.className = `check-item check-item-${isDanger ? 'danger' : 'passed'}`;

        const left = document.createElement('div');
        left.className = 'check-left';
        left.innerHTML = isDanger ? ICONS.checkDanger : ICONS.checkPassed;

        const name = document.createElement('span');
        name.className = 'check-name';
        name.textContent = ind.label || '';
        left.appendChild(name);

        const badge = document.createElement('span');
        badge.className = `check-status status-badge-${isDanger ? 'danger' : 'passed'}`;
        badge.textContent = ind.statusText || (isDanger ? 'Flagged' : 'Noted');

        li.appendChild(left);
        li.appendChild(badge);
        els.reasonsList.appendChild(li);
      });
      return;
    }

    if (els.reasonsHeading) els.reasonsHeading.textContent = 'Reasons behind classification';
    const fallbackChecks = Array.isArray(result.checks) ? result.checks : [];
    fallbackChecks.forEach(function (chk) {
      const li = document.createElement('li');
      li.className = 'check-item check-item-passed';

      const left = document.createElement('div');
      left.className = 'check-left';
      left.innerHTML = ICONS.checkPassed;

      const name = document.createElement('span');
      name.className = 'check-name';
      name.textContent = chk.name || '';
      left.appendChild(name);

      const badge = document.createElement('span');
      badge.className = 'check-status status-badge-passed';
      badge.textContent = chk.status || 'Passed';

      li.appendChild(left);
      li.appendChild(badge);
      els.reasonsList.appendChild(li);
    });
  }

  function renderFeatureChips(result) {
    if (!els.featuresGrid) return;
    els.featuresGrid.textContent = '';

    const features = result.features;
    if (!features || !features.valid) return;

    const { structure, domain, patterns } = features;
    const chips = [
      {
        text: `Protocol: ${features.protocol.replace(':', '').toUpperCase()}`,
        tone:
          features.isHttp && (patterns.keywords.allUniqueKeywords.length > 0 || domain.hasMisleadingDomain || structure.isPublicIp)
            ? 'flagged'
            : features.isHttp
              ? 'caution'
              : 'safe',
      },
      {
        text: `Length: ${structure.urlLength} chars`,
        tone: patterns.isVeryLongUrl ? 'caution' : 'neutral',
      },
      {
        text: `Domain: ${domain.registrableDomain || features.hostname}`,
        tone: domain.hasMisleadingDomain ? 'flagged' : 'neutral',
      },
      {
        text: `Subdomains: ${structure.subdomainCount}`,
        tone: domain.hasExcessiveSubdomains ? 'flagged' : 'neutral',
      },
      {
        text: `Hyphens: ${structure.hyphenCountInHost} host / ${structure.hyphenCountTotal} URL`,
        tone: patterns.hasExcessiveHyphens ? 'caution' : 'neutral',
      },
      {
        text: `Params: ${structure.queryParamCount} • Path segs: ${structure.pathSegmentCount}`,
        tone: 'neutral',
      },
      {
        text: `Special chars: ${structure.specialCharCount}`,
        tone: structure.specialCharCount >= 18 ? 'caution' : 'neutral',
      },
    ];

    if (structure.hasIpAddress) {
      chips.push({
        text: structure.isPrivateOrLocalIp ? 'Private/Local IP host' : 'Public raw IP address',
        tone: structure.isPrivateOrLocalIp ? 'caution' : 'flagged',
      });
    }
    if (domain.hasPunycode || domain.rawHostHasNonAscii) {
      chips.push({ text: 'Punycode / IDN', tone: 'caution' });
    }
    if (domain.isHighRiskTld) {
      chips.push({ text: `High-risk TLD (.${domain.tld})`, tone: 'flagged' });
    }
    if (patterns.hasAtInAuthority) {
      chips.push({ text: '"@" userinfo redirection', tone: 'flagged' });
    }
    if (patterns.isUrlShortener) {
      chips.push({ text: 'URL shortener', tone: 'caution' });
    }
    if (patterns.hasHexOrEncodedChars) {
      chips.push({
        text: `Encoded bytes: ${patterns.percentEncodedCount}`,
        tone: patterns.hasExcessivePercentEncoding || patterns.hasHexEscapeInAuthority ? 'flagged' : 'neutral',
      });
    }
    if (patterns.keywords.allUniqueKeywords.length > 0) {
      chips.push({
        text: `Keywords: ${patterns.keywords.allUniqueKeywords.slice(0, 4).join(', ')}`,
        tone: patterns.keywords.domainCredentialHits.length > 0 ? 'flagged' : 'caution',
      });
    }

    chips.forEach(function (item) {
      const span = document.createElement('span');
      span.className = 'feature-chip' + (item.tone !== 'neutral' ? ` chip-${item.tone}` : '');
      span.textContent = item.text;
      els.featuresGrid.appendChild(span);
    });
  }

  function writeScanResultDom(inputResult) {
    const result =
      inputResult && typeof inputResult === 'object'
        ? inputResult
        : {
            outcome: 'UNVERIFIED',
            classification: 'UNVERIFIED',
            riskLevel: 'Unverified',
            riskBadge: 'UNVERIFIED',
            statusTitle: 'Unable to Verify URL',
            statusDetail:
              'URL verification failed due to a technical failure or insufficient analysis data.',
          };
    const outcome = resolveScannerClassification(result);
    const isExactSafe = outcome === 'SAFE';
    const isPhishing = outcome === 'PHISHING';
    const isSuspicious = outcome === 'SUSPICIOUS';

    if (els.verdictCard) {
      const cardClass = isExactSafe
        ? 'status-safe'
        : outcome === 'UNVERIFIED' || outcome === 'EXEMPT'
          ? 'status-neutral'
          : 'status-phishing';
      els.verdictCard.className = `status-card scanner-verdict-card ${cardClass}`;
    }

    if (els.verdictIconWrapper) {
      els.verdictIconWrapper.innerHTML = isExactSafe ? ICONS.statusSafe : ICONS.statusDanger;
    }

    if (els.classificationBadge) {
      els.classificationBadge.className = 'scanner-classification-badge';
      if (isExactSafe) {
        els.classificationBadge.textContent = result.riskBadge || 'SAFE';
      } else if (outcome === 'EXEMPT') {
        els.classificationBadge.textContent = result.riskBadge || 'EXEMPT';
        els.classificationBadge.classList.add('badge-neutral');
      } else if (isPhishing) {
        els.classificationBadge.textContent = result.riskBadge || 'HIGH RISK';
        els.classificationBadge.classList.add('badge-high');
      } else if (isSuspicious) {
        els.classificationBadge.textContent = result.riskBadge || 'SUSPICIOUS';
        els.classificationBadge.classList.add('badge-medium');
      } else {
        els.classificationBadge.textContent = result.riskBadge || 'UNVERIFIED';
        els.classificationBadge.classList.add('badge-neutral');
      }
    }

    if (els.verdictTitle) {
      els.verdictTitle.textContent =
        result.statusTitle ||
        (isExactSafe
          ? 'Website Appears Safe'
          : outcome === 'EXEMPT'
            ? 'Exempt Page (Not Scanned)'
            : outcome === 'UNVERIFIED'
              ? 'Unable to Verify URL'
              : 'Suspicious URL Detected');
    }

    if (els.verdictExplanation) {
      els.verdictExplanation.textContent = result.statusDetail || '';
    }

    const detectedUrl = result.displayUrl || result.url || '';
    if (els.detectedUrl) {
      els.detectedUrl.textContent = detectedUrl;
      els.detectedUrl.setAttribute('title', detectedUrl);
    }

    const detectedDomain = result.detectedDomain || result.hostname || result.domain || '—';
    if (els.detectedDomain) {
      els.detectedDomain.textContent = detectedDomain;
      els.detectedDomain.setAttribute('title', detectedDomain);
    }

    if (els.impersonatedBrandRow && els.impersonatedBrand) {
      if (result.impersonatedBrand && result.impersonatedBrand.name) {
        const b = result.impersonatedBrand;
        els.impersonatedBrand.textContent = `${b.name} (${b.canonicalDomain})`;
        els.impersonatedBrandRow.style.display = 'flex';
      } else {
        els.impersonatedBrand.textContent = '—';
        els.impersonatedBrandRow.style.display = 'none';
      }
    }

    if (els.recommendation) {
      els.recommendation.textContent = result.recommendation || '';
    }

    renderReasons(result);
    renderFeatureChips(result);
  }

  function renderScanResult(result) {
    const resolvedResult =
      result && typeof result === 'object'
        ? result
        : {
            outcome: 'UNVERIFIED',
            classification: 'UNVERIFIED',
            riskLevel: 'Unverified',
            riskBadge: 'UNVERIFIED',
            statusTitle: 'Unable to Verify URL',
            statusDetail:
              'URL verification failed due to a technical failure or insufficient analysis data.',
          };
    currentScannerResult = resolvedResult;

    if (els.scanBtn) els.scanBtn.disabled = false;

    transitionOutputSection(els.resultsBox, {
      displayMode: 'flex',
      onBeforeSwap: function () {
        applyVisualTheme(resolvedResult.outcome || resolvedResult.classification, resolvedResult);
        writeScanResultDom(resolvedResult);
      },
    });
  }

  function runSharedDetection(targetUrl) {
    if (isExtensionRuntime()) {
      return new Promise(function (resolve) {
        try {
          chrome.runtime.sendMessage(
            { type: 'PHISHGUARD_MANUAL_SCAN', url: targetUrl },
            function (resp) {
              if (!chrome.runtime.lastError && resp && resp.ok && resp.result) {
                resolve(resp.result);
                return;
              }
              resolve(
                window.PhishGuardDetector
                  ? window.PhishGuardDetector.analyzeUrl(targetUrl)
                  : null
              );
            }
          );
        } catch (_) {
          resolve(
            window.PhishGuardDetector
              ? window.PhishGuardDetector.analyzeUrl(targetUrl)
              : null
          );
        }
      });
    }

    return Promise.resolve(
      window.PhishGuardDetector ? window.PhishGuardDetector.analyzeUrl(targetUrl) : null
    );
  }

  async function handleScanSubmit(e) {
    ensureElements();
    if (e) e.preventDefault();
    clearValidationError();

    const validation = validateUserUrlInput(els.input ? els.input.value : '');
    if (!validation.valid) {
      showValidationError(validation.error);
      if (!currentScannerResult) {
        applyVisualTheme('idle', null, { explicitSubtitle: 'Manual URL Scanner' });
      }
      return;
    }

    const scanInput = validation.rawUrl || validation.normalizedUrl;
    lastScannedUrl = scanInput;
    setLoading(true);
    try {
      const [result] = await Promise.all([
        runSharedDetection(scanInput),
        new Promise(function (r) {
          setTimeout(r, 160);
        }),
      ]);

      // Populate full features locally if service worker stripped compact feature tree
      if (result && !result.features && window.PhishGuardURLAnalyzer) {
        result.features = window.PhishGuardURLAnalyzer.extractFeatures(scanInput);
      }

      renderScanResult(result);
    } catch (_) {
      if (els.scanBtn) els.scanBtn.disabled = false;
      renderScanResult({
        outcome: 'UNVERIFIED',
        classification: 'UNVERIFIED',
        riskLevel: 'Unverified',
        riskBadge: 'UNVERIFIED',
        displayUrl: scanInput,
        url: scanInput,
        detectedDomain: '',
        statusTitle: 'Unable to Verify URL',
        statusDetail:
          'URL verification could not be completed due to a technical failure. PhishGuard cannot confirm whether this site is safe or phishing.',
        recommendation:
          'Verification failed before analysis completed. Confirm the website destination independently before sharing sensitive details.',
        indicators: [],
      });
    }
  }

  function updateOpenInTabVisibility() {
    if (!els.openInTabBtn) return;
    const params = new URLSearchParams(window.location.search);
    const openedFromPopup = params.get('from') === 'popup';
    const inFullTab =
      isEmbeddedMode &&
      window.PhishGuard &&
      ((typeof window.PhishGuard.isFullTabMode === 'function' && window.PhishGuard.isFullTabMode()) ||
        (typeof window.PhishGuard.isWarningMode === 'function' && window.PhishGuard.isWarningMode()));
    const showOpenInTab = isEmbeddedMode
      ? isExtensionRuntime() && !inFullTab
      : isExtensionRuntime() && openedFromPopup;
    els.openInTabBtn.style.display = showOpenInTab ? 'inline-flex' : 'none';
  }

  function handleEmbeddedActivated(previousTone) {
    updateOpenInTabVisibility();
    if (!currentScannerResult) {
      applyVisualTheme('idle', null, {
        previousTone: previousTone,
        explicitSubtitle: 'Manual URL Scanner',
      });
      return;
    }
    applyVisualTheme(
      currentScannerResult.outcome || currentScannerResult.classification || currentScannerClassification,
      currentScannerResult,
      { previousTone: previousTone }
    );
  }

  function getPassedTargetUrlParam() {
    try {
      const params = new URLSearchParams(window.location.search);
      return (
        params.get('scanUrl') ||
        params.get('targetUrl') ||
        params.get('url') ||
        params.get('prefill') ||
        ''
      );
    } catch (_) {
      return '';
    }
  }

  async function loadScannedUrl(rawTargetUrl, options) {
    ensureElements();
    const opts = options || {};
    const candidate = String(rawTargetUrl || '').trim();
    if (!candidate) return null;

    if (isExtensionInternalUrl(candidate)) {
      clearValidationError();
      showValidationError('Cannot scan an internal PhishGuard extension URL. Please enter an external http:// or https:// website URL.');
      applyVisualTheme('idle', null, { explicitSubtitle: 'Manual URL Scanner' });
      return null;
    }

    if (els.input) {
      els.input.value = candidate;
    }
    if (opts.autoScan === false) {
      return null;
    }
    await handleScanSubmit();
    return currentScannerResult;
  }

  function getTargetUrlForFullInterface() {
    const inputVal = els.input && els.input.value ? els.input.value.trim() : '';
    const rawCandidate =
      inputVal ||
      lastScannedUrl ||
      (currentScannerResult && !isExtensionInternalUrl(currentScannerResult.url)
        ? currentScannerResult.url || currentScannerResult.displayUrl
        : '');
    if (!rawCandidate || isExtensionInternalUrl(rawCandidate)) {
      return '';
    }
    return rawCandidate;
  }

  function buildFullInterfaceTabUrl(targetUrl) {
    const query = targetUrl
      ? `?scanUrl=${encodeURIComponent(targetUrl)}&autoScan=1`
      : '';
    return chrome.runtime.getURL('scanner.html' + query);
  }

  function setupNavigationControls() {
    const params = new URLSearchParams(window.location.search);
    const openedFromPopup = params.get('from') === 'popup';

    if (els.openInTabBtn) {
      updateOpenInTabVisibility();
      els.openInTabBtn.addEventListener('click', function () {
        if (chrome.tabs && chrome.tabs.create) {
          const targetUrl = getTargetUrlForFullInterface();
          const typedVal = els.input && els.input.value ? els.input.value.trim() : '';
          if (typedVal && isExtensionInternalUrl(typedVal)) {
            showValidationError('Cannot scan an internal PhishGuard extension URL.');
            return;
          }
          if (targetUrl) {
            const validation = validateUserUrlInput(targetUrl);
            if (!validation.valid) {
              showValidationError(validation.error);
              return;
            }
          }
          chrome.tabs.create({ url: buildFullInterfaceTabUrl(targetUrl) });
        }
      });
    }

    if (els.backToTabBtn) {
      if (!isEmbeddedMode && !openedFromPopup && isExtensionRuntime()) {
        els.backToTabBtn.style.display = 'none';
      } else {
        els.backToTabBtn.style.display = 'inline-flex';
        els.backToTabBtn.addEventListener('click', function () {
          if (isEmbeddedMode && window.PhishGuard && typeof window.PhishGuard.openTabStatus === 'function') {
            window.PhishGuard.openTabStatus();
            return;
          }
          const transitions = getTransitions();
          if (transitions && !transitions.prefersReducedMotion() && els.scannerView && els.scannerView.classList) {
            els.scannerView.classList.add('panel-view-leaving');
            setTimeout(function () {
              window.location.href = './index.html';
            }, 190);
          } else {
            window.location.href = './index.html';
          }
        });
      }
    }
  }

  function setupEventListeners() {
    if (els.form) {
      els.form.addEventListener('submit', handleScanSubmit);
    }

    if (els.clearBtn) {
      els.clearBtn.addEventListener('click', function () {
        if (els.input) {
          els.input.value = '';
          els.input.focus();
        }
        clearValidationError();
        if (els.scanBtn) els.scanBtn.disabled = false;
        currentScannerResult = null;
        currentScannerClassification = 'idle';
        lastScannedUrl = '';
        transitionOutputSection(els.emptyHint, {
          displayMode: 'block',
          onBeforeSwap: function () {
            applyVisualTheme('idle', null, { explicitSubtitle: 'Manual URL Scanner' });
          },
        });
      });
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    initElements();
    setupNavigationControls();
    setupEventListeners();

    const transitions = getTransitions();
    if (transitions) {
      transitions.playAllVideos(document);
    } else {
      playVideo(els.bgVideo);
      playVideo(els.panelBgVideo);
    }

    const passedUrl = getPassedTargetUrlParam();
    if (passedUrl && !isEmbeddedMode) {
      loadScannedUrl(passedUrl, { autoScan: true });
      return;
    }

    if (!isEmbeddedMode) {
      applyVisualTheme('idle', null, { skipAccent: true, skipHeaderPulse: true });
      if (els.input) {
        els.input.focus();
      }
    }
  });

  window.PhishGuardScanner = {
    validateUserUrlInput,
    scanUrl: handleScanSubmit,
    loadScannedUrl,
    buildFullInterfaceTabUrl,
    getTargetUrlForFullInterface,
    onActivated: handleEmbeddedActivated,
  };
})();
