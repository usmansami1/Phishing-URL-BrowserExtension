/**
 * PhishGuard - Core Phishing Detection Engine
 * Coordinates URL feature extraction, heuristic risk scoring, optional
 * threat-intelligence lookup, and UI-ready classification reporting.
 */
(function (root, factory) {
  let analyzer = root.PhishGuardURLAnalyzer;
  let scorer = root.PhishGuardRiskScorer;

  if (typeof module === 'object' && module.exports && (!analyzer || !scorer)) {
    analyzer = analyzer || require('./urlAnalyzer.js');
    scorer = scorer || require('./riskScorer.js');
  }

  const api = factory(analyzer, scorer);
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  }
  root.PhishGuardDetector = api;
})(typeof globalThis !== 'undefined' ? globalThis : self, function (URLAnalyzer, RiskScorer) {
  'use strict';

  const OUTCOMES = (RiskScorer && RiskScorer.OUTCOMES) || {
    SAFE: 'SAFE',
    SUSPICIOUS: 'SUSPICIOUS',
    PHISHING: 'PHISHING',
    UNVERIFIED: 'UNVERIFIED',
  };

  function buildUnsupportedResult(rawUrl, reason, meta) {
    const isExempt = Boolean(meta && (meta.exempt || meta.isInternalBrowserPage));
    const isPdfViewer = Boolean(isExempt && meta && meta.isPdfViewer);
    const isLocalFile = Boolean(isExempt && meta && meta.isLocalFile);
    const exemptTitle = isPdfViewer
      ? 'Browser PDF Viewer (Exempt)'
      : isLocalFile
        ? 'Local File Document (Exempt)'
        : 'Internal Browser Page (Exempt)';

    return {
      supported: false,
      exempt: isExempt,
      isInternalBrowserPage: isExempt,
      isPdfViewer,
      isLocalFile,
      exemptCategory: isExempt ? (meta && meta.exemptCategory) || 'browser_internal' : '',
      exemptScheme: isExempt ? (meta && meta.exemptScheme) || '' : '',
      valid: false,
      verificationFailed: !isExempt,
      url: String(rawUrl || ''),
      displayUrl: String(rawUrl || (isExempt ? 'Browser internal or local page' : 'Unverified URL')),
      domain: '',
      detectedDomain: '',
      impersonatedBrand: null,
      uiState: isExempt ? 'neutral' : 'phishing',
      outcome: isExempt ? 'EXEMPT' : OUTCOMES.UNVERIFIED,
      classification: isExempt ? 'EXEMPT' : OUTCOMES.UNVERIFIED,
      riskBadge: isExempt ? 'EXEMPT' : 'UNVERIFIED',
      classificationLabel: isExempt ? 'Exempt (Not Scanned)' : 'Unverified (Verification Failed)',
      shouldBlock: !isExempt,
      riskScore: 0,
      riskLevel: isExempt ? 'Exempt' : 'Unverified',
      severity: isExempt ? 'none' : 'unknown',
      headerSubtitle: isExempt ? 'Exempt Page • Not Scanned' : '⚠️ Caution: Verification Failed',
      statusTitle: isExempt ? exemptTitle : 'Unable to Verify URL',
      statusDetail:
        reason ||
        (isExempt
          ? 'Browser-internal, extension, built-in PDF viewer, and local file URLs are exempt from website phishing detection.'
          : 'URL verification could not be completed due to a technical failure or insufficient analysis data. PhishGuard cannot confirm whether this site is safe or phishing.'),
      checksHeading: 'Verification details',
      checks: isExempt
        ? [
            { name: 'URL scheme scope', status: 'Exempt', type: 'passed' },
            { name: 'Phishing rules executed', status: 'Skipped (0 rules)', type: 'passed' },
            { name: 'Website classification', status: 'Not applicable', type: 'passed' },
          ]
        : [
            { name: 'URL verification', status: 'Failed', type: 'passed' },
            { name: 'Confirmed phishing indicators', status: 'None confirmed', type: 'passed' },
          ],
      recommendation: isExempt
        ? 'PhishGuard only analyzes external HTTP/HTTPS websites. Browser system pages, extension pages, Chrome PDF viewer URLs, and local file:// documents are excluded from phishing scanning.'
        : 'Verification failed before analysis could complete. Confirm this URL manually before entering passwords or sensitive information.',
      reasons: [],
      indicators: [],
      rules: [],
      ruleSummary: { totalTriggered: 0, byCategory: {}, byStrength: { weak: 0, medium: 0, strong: 0 } },
      features: null,
      assessmentType: isExempt ? 'exempt' : 'rule_based',
      isVerifiedMalicious: false,
      analyzedAt: Date.now(),
    };
  }

  function buildChecksForUI(features, scoreResult) {
    const outcome = scoreResult && scoreResult.classification;
    if (outcome === OUTCOMES.UNVERIFIED) {
      return [
        {
          name: 'URL verification',
          status: 'Failed',
          type: 'passed',
        },
        {
          name: 'Confirmed phishing indicators',
          status: 'None confirmed',
          type: 'passed',
        },
      ];
    }

    if (outcome === OUTCOMES.SAFE) {
      const { structure, domain, patterns } = features;
      const structureOk = !structure.hasIpAddress && !patterns.isVeryLongUrl;
      const domainOk = !domain.hasMisleadingDomain && !domain.isHighRiskTld;
      const charsOk = !patterns.hasAtInAuthority && !patterns.hasDoubleEncoding;

      const checks = [
        {
          name: 'URL structure',
          status: structureOk ? 'Passed' : 'Noted',
          type: 'passed',
        },
        {
          name: 'Domain indicators',
          status: domainOk ? 'Passed' : 'Noted',
          type: 'passed',
        },
        {
          name: 'Suspicious characters',
          status: charsOk ? 'Passed' : 'Noted',
          type: 'passed',
        },
      ];

      // Surface HTTP connection-security note or minor indicators without declaring plain HTTP phishing
      if (features.isHttp && !features.structure.isPrivateOrLocalIp) {
        checks[2] = {
          name: 'Unencrypted HTTP connection',
          status: 'Not Secure',
          type: 'passed',
        };
      } else if (scoreResult.indicators.length > 0 && scoreResult.score >= 12) {
        const topNote = scoreResult.indicators[0];
        checks[2] = {
          name: topNote.label,
          status: topNote.statusText || 'Noted',
          type: 'passed',
        };
      }

      return checks;
    }

    // SUSPICIOUS or PHISHING: surface top highest-weight reasons concisely (max 4 to fit panel cleanly)
    const topIndicators = scoreResult.indicators.slice(0, 4);
    if (topIndicators.length === 0) {
      return [
        {
          name: 'Heuristic risk threshold exceeded',
          status: 'Flagged',
          type: 'danger',
        },
      ];
    }

    return topIndicators.map((ind) => ({
      name: ind.label,
      status: ind.statusText || 'Flagged',
      type: 'danger',
    }));
  }

  function buildPresentationCopy(scoreResult) {
    const outcome = scoreResult && scoreResult.classification;

    if (outcome === OUTCOMES.SAFE) {
      const hasMinorNotes = Boolean(scoreResult && scoreResult.rules && scoreResult.rules.length > 0);
      return {
        uiState: 'safe',
        shouldBlock: false,
        riskBadge: 'SAFE',
        classificationLabel: 'Safe',
        headerSubtitle: 'URL Security Extension',
        statusTitle: 'Website Appears Safe',
        statusDetail: hasMinorNotes
          ? 'Analysis completed cleanly. No meaningful suspicious or phishing indicators were detected.'
          : 'No suspicious or phishing indicators were found during rule analysis.',
        checksHeading: 'Security checks',
        recommendation:
          'No suspicious indicators were found. Continue browsing with standard caution.',
      };
    }

    if (outcome === OUTCOMES.PHISHING) {
      return {
        uiState: 'phishing',
        shouldBlock: true,
        riskBadge: 'HIGH RISK',
        classificationLabel: 'Phishing / High Risk',
        headerSubtitle: '⚠️ Threat Warning: Phishing Website Detected',
        statusTitle: 'Potential Phishing Detected',
        statusDetail: 'Strong phishing or deceptive structural indicators were detected by the rule engine.',
        checksHeading: 'Detected reasons',
        recommendation:
          'Do not enter passwords, payment details, or other personal information on this website.',
      };
    }

    if (outcome === OUTCOMES.SUSPICIOUS) {
      return {
        uiState: 'phishing',
        shouldBlock: true,
        riskBadge: 'SUSPICIOUS',
        classificationLabel: 'Suspicious',
        headerSubtitle: '⚠️ Caution: Suspicious URL Patterns',
        statusTitle: 'Suspicious URL Detected',
        statusDetail:
          'Meaningful suspicious indicators were detected, though there is insufficient evidence for a confirmed phishing classification.',
        checksHeading: 'Detected reasons',
        recommendation:
          'Exercise caution before signing in or sharing personal details. Verify the exact domain spelling carefully.',
      };
    }

    return {
      uiState: 'phishing',
      shouldBlock: true,
      riskBadge: 'UNVERIFIED',
      classificationLabel: 'Unverified (Verification Failed)',
      headerSubtitle: '⚠️ Caution: Verification Failed',
      statusTitle: 'Unable to Verify URL',
      statusDetail:
        (scoreResult && scoreResult.failureReason) ||
        'URL verification could not be completed due to a technical failure or insufficient analysis data. PhishGuard cannot confirm whether this site is safe or phishing.',
      checksHeading: 'Verification details',
      recommendation:
        'Verification failed before analysis completed. Confirm the website destination independently before sharing sensitive details.',
    };
  }

  function analyzeUrl(rawUrl, options) {
    const opts = options || {};

    if (!URLAnalyzer || !RiskScorer) {
      return buildUnsupportedResult(rawUrl, 'Detection engine components failed to load.');
    }

    if (!rawUrl || typeof rawUrl !== 'string') {
      return buildUnsupportedResult('', 'Insufficient URL data provided for analysis.');
    }

    try {
      const exemptInfo =
        typeof URLAnalyzer.classifyExemptUrl === 'function'
          ? URLAnalyzer.classifyExemptUrl(rawUrl)
          : {
              isExempt: /^(chrome|chrome-extension|extension|edge|chrome-search|chrome-devtools|chrome-untrusted|devtools|brave|opera|vivaldi|about|file):/i.test(
                rawUrl.trim()
              ),
              isInternalBrowserPage: true,
              isPdfViewer: /^chrome-extension:\/\/mhjfbmdgcfjbbpaeojofohoefgiehjai\b/i.test(rawUrl.trim()),
              isLocalFile: /^file:/i.test(rawUrl.trim()),
              category: /^file:/i.test(rawUrl.trim()) ? 'local_file' : 'browser_internal',
              scheme: '',
              reason: 'Exempt browser-internal, extension, or local file URL excluded from phishing scanning.',
            };

      if (exemptInfo && exemptInfo.isExempt) {
        return buildUnsupportedResult(rawUrl, exemptInfo.reason, {
          exempt: true,
          isInternalBrowserPage: true,
          isPdfViewer: exemptInfo.isPdfViewer,
          isLocalFile: exemptInfo.isLocalFile,
          exemptCategory: exemptInfo.category,
          exemptScheme: exemptInfo.scheme,
        });
      }

      if (!URLAnalyzer.isSupportedUrl(rawUrl)) {
        return buildUnsupportedResult(
          rawUrl,
          'Unsupported URL scheme prevented automated verification.'
        );
      }

      const features = URLAnalyzer.extractFeatures(rawUrl);
      if (!features || !features.valid || !features.supported) {
        return buildUnsupportedResult(
          rawUrl,
          (features && features.error) || 'Malformed URL or insufficient analysis data.'
        );
      }

      const scoreResult = RiskScorer.scoreFeatures(
        features,
        {
          pageSignals: opts.pageSignals || null,
          registrationInfo: opts.registrationInfo || null,
        },
        opts.scoringConfig || null
      );

      if (!scoreResult || !(scoreResult.classification in OUTCOMES)) {
        return buildUnsupportedResult(
          rawUrl,
          'Detection pipeline returned an invalid or incomplete classification result.'
        );
      }

      const copy = buildPresentationCopy(scoreResult);
      const checks = buildChecksForUI(features, scoreResult);

      return {
        supported: true,
        valid: true,
        verificationFailed: Boolean(scoreResult.verificationFailed),
        url: features.normalizedUrl,
        displayUrl: features.normalizedUrl,
        domain: features.domain.registrableDomain || features.hostname,
        detectedDomain: features.hostname,
        hostname: features.hostname,
        impersonatedBrand: null,
        uiState: copy.uiState,
        outcome: scoreResult.classification,
        classification: scoreResult.classification,
        riskBadge: copy.riskBadge,
        classificationLabel: copy.classificationLabel,
        shouldBlock: copy.shouldBlock,
        riskScore: scoreResult.score,
        riskLevel: scoreResult.riskLevel,
        severity: scoreResult.severity,
        headerSubtitle: copy.headerSubtitle,
        statusTitle: copy.statusTitle,
        statusDetail: copy.statusDetail,
        checksHeading: copy.checksHeading,
        checks,
        recommendation: copy.recommendation,
        reasons: scoreResult.indicators.map((ind) => ind.label),
        indicators: scoreResult.indicators,
        rules: scoreResult.rules || scoreResult.indicators,
        ruleSummary: scoreResult.ruleSummary || null,
        categoryScores: scoreResult.categoryScores,
        synergyAdded: scoreResult.synergyAdded,
        overrideApplied: scoreResult.overrideApplied || null,
        features,
        assessmentType: 'rule_based',
        isVerifiedMalicious: false,
        analyzedAt: Date.now(),
      };
    } catch (err) {
      return buildUnsupportedResult(
        rawUrl,
        `Technical error during URL analysis: ${(err && err.message) || 'unexpected failure'}.`
      );
    }
  }

  return {
    OUTCOMES,
    analyzeUrl,
  };
});
