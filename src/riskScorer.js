/**
 * PhishGuard - Risk Aggregation & Classification Module
 * Aggregates rules evaluated by RuleEngine using configurable thresholds,
 * per-category caps, synergy escalation, and high-priority impersonation floors
 * to avoid double counting and single-feature false positives.
 */
(function (root, factory) {
  let ruleEngine = root.PhishGuardRuleEngine;
  if (typeof module === 'object' && module.exports && !ruleEngine) {
    ruleEngine = require('./ruleEngine.js');
  }
  const api = factory(ruleEngine);
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  }
  root.PhishGuardRiskScorer = api;
})(typeof globalThis !== 'undefined' ? globalThis : self, function (RuleEngine) {
  'use strict';

  const OUTCOMES = {
    SAFE: 'SAFE',
    SUSPICIOUS: 'SUSPICIOUS',
    PHISHING: 'PHISHING',
    UNVERIFIED: 'UNVERIFIED',
  };

  const DEFAULT_RULE_THRESHOLDS = RuleEngine ? RuleEngine.DEFAULT_RULE_THRESHOLDS : {};

  const DEFAULT_CONFIG = {
    thresholds: {
      medium: 30,
      high: 60,
    },
    overrides: {
      multiObfuscationMediumFloor: 48,
    },
    ruleThresholds: { ...DEFAULT_RULE_THRESHOLDS },
    categoryCaps: {
      urlComplexity: 20,
      charManipulation: 48,
      hostStructure: 38,
      brandImpersonation: 85,
      lureKeywords: 30,
      pathAndQuery: 42,
      redirectPatterns: 38,
      transportAndProtocol: 24,
      domainReputation: 32,
      indicatorCombinations: 40,
      pageContext: 16,
    },
    weights: {
      // Category A: URL Length & Complexity
      urlLengthExcessive: 9,
      veryLongUrl: 6,
      unusuallyLongUrl: 3,
      domainLengthExtreme: 9,
      longHostname: 4,
      subdomainLabelExtreme: 8,
      subdomainSectionLong: 4,
      pathLengthExcessive: 5,
      pathLengthLong: 3,
      pathSegmentsExcessive: 6,
      pathSegmentsDeep: 3,
      queryParamsExcessive: 6,
      queryParamsMany: 3,
      queryParamValueExtreme: 5,
      queryParamValueLong: 3,
      multipleFragments: 8,
      longFragment: 4,
      excessiveDotsHigh: 8,
      elevatedDots: 3,
      hostHyphensFourPlus: 12,
      hostHyphensThree: 4,
      hostHyphensTwo: 2,
      underscoreInHost: 9,
      excessiveUnderscoresUrl: 3,
      excessiveDigitsHigh: 5,
      excessiveDigitsModerate: 2,
      alnumClutterHost: 9,
      alnumMixHost: 4,
      repeatedSpecialChars: 5,
      highSpecialCharRatio: 7,
      elevatedSpecialCharRatio: 3,
      highPunctuationDensity: 4,
      domainLabelExtreme: 9,
      domainLabelLong: 4,
      consecutiveSeparators: 8,
      repeatedCharSequences: 4,
      domainHighEntropy: 12,

      // Category B: Character Manipulation & Obfuscation
      atInAuthority: 34,
      multipleAtSymbols: 16,
      encodedAtSymbol: 18,
      hexEscapeInAuthority: 18,
      doublePercentEncoding: 16,
      encodedDotsOrSlashes: 10,
      heavyPercentEncoding: 12,
      excessivePercentEncoding: 7,
      percentEncodingPresent: 2,
      hexSequences: 6,
      punycodeIdn: 12,
      mixedScriptsInDomain: 34,
      confusableUnicodeChars: 18,
      bidiUnicodeChars: 42,
      invisibleUnicodeChars: 36,
      unusualTilde: 5,
      backslashInAuthority: 28,
      backslashInUrl: 12,
      multipleSlashesAfterHost: 9,
      obfuscatedLureKeyword: 34,
      medialDigitSubstitution: 32,
      boundaryDigitSubstitution: 30,
      domainShapedUserinfo: 14,

      // Category C: Domain & Host Structure
      obfuscatedIpAddress: 34,
      publicIpAddress: 30,
      privateIpUnexpected: 28,
      privateIpBaseline: 2,
      subdomainsFivePlus: 22,
      subdomainsThreeFour: 12,
      subdomainsTwo: 2,
      repeatedDomainLabels: 10,
      suspiciousDomainPrefix: 10,
      suspiciousDomainSuffix: 9,
      multiHyphenSldHigh: 10,
      multiHyphenSld: 4,
      numericHeavyDomain: 11,
      numericRegisteredDomain: 4,
      unusualHostnameFormat: 12,
      embeddedDomainInSubdomain: 32,
      multipleDomainStrings: 11,

      // Category D: Structural Mimicry & Lookalikes
      idnHomoglyphMimicry: 22,

      // Category E: Keywords & Combinations
      keywordsThreePlusDomain: 18,
      keywordsThreePlusPath: 11,
      keywordsTwoDomain: 11,
      keywordsTwoPath: 5,
      keywordsOneDomain: 5,
      keywordsOnePath: 2,
      multipleUrgencyKeywords: 14,
      passwordKeywordDomain: 14,
      passwordKeywordPath: 7,
      paymentKeywordSuspiciousDomain: 12,

      // Category F: Path & Query
      loginPathSuspiciousDomain: 12,
      suspiciousLoginFilenameHigh: 11,
      suspiciousLoginFilename: 5,
      fakeVerificationFilename: 10,
      passwordResetPath: 9,
      paymentCheckoutPath: 11,
      longRandomPathSegment: 4,
      randomQueryValuesMulti: 6,
      randomQueryValues: 3,
      encodedQueryParams: 7,
      doubleExtensionFile: 38,
      executableExtension: 22,
      archiveExtension: 7,
      misleadingDocName: 14,
      scriptExtension: 5,
      extensionWithSuspiciousQuery: 10,
      queryContainsCompleteUrl: 5,

      // Category G: Redirect & Parameter Patterns
      nestedRedirectUrls: 18,
      multipleRedirectParams: 14,
      encodedExternalRedirect: 12,
      openRedirectStructure: 12,
      redirectToUnrelatedDomain: 10,

      // Category H: Transport & Protocol Context
      httpWithCredentialContext: 16,
      httpPlainBaseline: 4,
      httpsFalseSecurityNote: 0,
      nonStandardPort: 11,
      unusualProtocolFormat: 6,
      httpsInDomainName: 11,
      protocolInPath: 10,
      multipleProtocolStrings: 10,

      // Category I: TLD & Domain Reputation
      highRiskTld: 18,
      moderateRiskTld: 7,
      veryRecentDomain: 24,
      newlyRegisteredDomain: 14,
      registrationUnavailable: 2,

      // Page Context Signals (content.js)
      passwordFieldOnHttp: 12,
      crossOriginFormOnSuspiciousHost: 10,

      // Category J: Multi-Indicator Combinations
      comboIpPlusCredential: 22,
      comboPunycodePlusLure: 22,
      comboRandomDomainPlusKeywords: 20,
      comboEncodedRedirectPlusLure: 22,
      comboKeywordsPlusNewDomain: 20,
      comboParamsPlusEncodedExternal: 14,
      comboMultipleObfuscations: 26,
      comboAuthorityDeception: 26,
      comboRiskyTldPlusLure: 20,
      comboDeceptiveHostLures: 22,
      comboHiddenFragmentPayload: 20,
      comboRedirectSuspiciousTarget: 22,
    },
    synergyBonus: {
      twoCategories: 6,
      threeCategories: 14,
      fourOrMoreCategories: 20,
      significantCategoryMinScore: 10,
    },
  };

  function cloneConfig(overrides) {
    if (!overrides || typeof overrides !== 'object') {
      return JSON.parse(JSON.stringify(DEFAULT_CONFIG));
    }
    return {
      thresholds: { ...DEFAULT_CONFIG.thresholds, ...(overrides.thresholds || {}) },
      overrides: { ...DEFAULT_CONFIG.overrides, ...(overrides.overrides || {}) },
      ruleThresholds: { ...DEFAULT_CONFIG.ruleThresholds, ...(overrides.ruleThresholds || {}) },
      categoryCaps: { ...DEFAULT_CONFIG.categoryCaps, ...(overrides.categoryCaps || {}) },
      weights: { ...DEFAULT_CONFIG.weights, ...(overrides.weights || {}) },
      synergyBonus: { ...DEFAULT_CONFIG.synergyBonus, ...(overrides.synergyBonus || {}) },
    };
  }

  function classifyScore(score, thresholds, analysisContext) {
    const ctx = analysisContext || {};
    if (!ctx.analysisComplete) {
      return {
        outcome: OUTCOMES.UNVERIFIED,
        classification: OUTCOMES.UNVERIFIED,
        riskLevel: 'Unverified',
        severity: 'unknown',
        verificationFailed: true,
      };
    }

    const strongCount = Number(ctx.strongCount) || 0;
    const mediumCount = Number(ctx.mediumCount) || 0;
    const meaningfulCount = strongCount + mediumCount;
    const significantCategories = Number(ctx.significantCategoryCount) || 0;
    const hasOverride = Boolean(ctx.overrideApplied);

    // Require strong evidence or multi-category/medium corroboration for PHISHING
    if (
      score >= thresholds.high &&
      (strongCount >= 1 || mediumCount >= 2 || significantCategories >= 2)
    ) {
      return {
        outcome: OUTCOMES.PHISHING,
        classification: OUTCOMES.PHISHING,
        riskLevel: 'High Risk',
        severity: 'high',
        verificationFailed: false,
      };
    }

    // Weak minor characteristics alone cannot promote a clean/ordinary site to SUSPICIOUS
    if (
      score >= thresholds.medium &&
      (meaningfulCount >= 1 || significantCategories >= 2 || hasOverride)
    ) {
      return {
        outcome: OUTCOMES.SUSPICIOUS,
        classification: OUTCOMES.SUSPICIOUS,
        riskLevel: 'Suspicious',
        severity: 'medium',
        verificationFailed: false,
      };
    }

    // Completed analysis with zero meaningful suspicious indicators => SAFE
    return {
      outcome: OUTCOMES.SAFE,
      classification: OUTCOMES.SAFE,
      riskLevel: 'Safe',
      severity: 'low',
      verificationFailed: false,
    };
  }

  function summarizeRules(rules) {
    const byCategory = {};
    const byStrength = { weak: 0, medium: 0, strong: 0 };
    for (let i = 0; i < rules.length; i++) {
      const r = rules[i];
      byCategory[r.category] = (byCategory[r.category] || 0) + 1;
      if (r.indicatorStrength in byStrength) {
        byStrength[r.indicatorStrength] += 1;
      }
    }
    return {
      totalTriggered: rules.length,
      byCategory,
      byStrength,
    };
  }

  function buildUnverifiedScoreResult(config, reason) {
    return {
      score: 0,
      outcome: OUTCOMES.UNVERIFIED,
      classification: OUTCOMES.UNVERIFIED,
      riskLevel: 'Unverified',
      severity: 'unknown',
      verificationFailed: true,
      failureReason: reason || 'Insufficient URL analysis data or rule pipeline failure.',
      indicators: [],
      rules: [],
      ruleSummary: {
        totalTriggered: 0,
        byCategory: {},
        byStrength: { weak: 0, medium: 0, strong: 0 },
        pipelineStagesExecuted: [],
      },
      significantCategoryCount: 0,
      categoryScores: {},
      synergyAdded: 0,
      overrideApplied: null,
      configUsed: config,
    };
  }

  function scoreFeatures(features, contextOrSignals, customConfig) {
    const config = cloneConfig(customConfig);

    if (!features || !features.valid || !features.supported) {
      return buildUnverifiedScoreResult(config, 'Invalid, malformed, or unsupported URL features.');
    }

    if (!RuleEngine || typeof RuleEngine.evaluateRules !== 'function') {
      return buildUnverifiedScoreResult(config, 'Rule evaluation engine is unavailable.');
    }

    const evalContext =
      contextOrSignals &&
      ('pageSignals' in contextOrSignals || 'registrationInfo' in contextOrSignals)
        ? contextOrSignals
        : { pageSignals: contextOrSignals || null, registrationInfo: null };

    const evaluated = RuleEngine.evaluateRules(features, evalContext, config);
    if (
      !evaluated ||
      !Array.isArray(evaluated.rules) ||
      !Array.isArray(evaluated.pipelineStagesExecuted) ||
      evaluated.pipelineStagesExecuted.length === 0
    ) {
      return buildUnverifiedScoreResult(config, 'Detection rule pipeline did not execute cleanly.');
    }

    const rules = evaluated.rules.slice();
    const rawCategorySums = {};
    let strongCount = 0;
    let mediumCount = 0;
    for (let i = 0; i < rules.length; i++) {
      const r = rules[i];
      rawCategorySums[r.category] = (rawCategorySums[r.category] || 0) + r.weight;
      if (r.indicatorStrength === 'strong') strongCount += 1;
      else if (r.indicatorStrength === 'medium') mediumCount += 1;
    }

    let cappedTotal = 0;
    let significantCategoryCount = 0;
    const cappedBreakdown = {};

    for (const [category, rawSum] of Object.entries(rawCategorySums)) {
      const cap = config.categoryCaps[category] ?? 30;
      const capped = Math.min(rawSum, cap);
      cappedBreakdown[category] = capped;
      cappedTotal += capped;
      if (category !== 'indicatorCombinations' && capped >= config.synergyBonus.significantCategoryMinScore) {
        significantCategoryCount += 1;
      }
    }

    let synergyAdded = 0;
    if (significantCategoryCount >= 4) {
      synergyAdded = config.synergyBonus.fourOrMoreCategories;
    } else if (significantCategoryCount === 3) {
      synergyAdded = config.synergyBonus.threeCategories;
    } else if (significantCategoryCount === 2) {
      synergyAdded = config.synergyBonus.twoCategories;
    }

    let finalScore = Math.max(0, Math.min(100, Math.round(cappedTotal + synergyAdded)));
    let overrideApplied = null;

    if (evaluated.obfuscationTechniques >= 2) {
      const floor = config.overrides.multiObfuscationMediumFloor ?? 48;
      if (finalScore < floor) {
        finalScore = floor;
        overrideApplied = 'multi_obfuscation';
      }
    }

    const levelInfo = classifyScore(finalScore, config.thresholds, {
      analysisComplete: true,
      ruleCount: rules.length,
      strongCount,
      mediumCount,
      significantCategoryCount,
      overrideApplied,
    });

    // Highest weight first for concise UI reporting
    rules.sort((a, b) => b.weight - a.weight);

    return {
      score: finalScore,
      outcome: levelInfo.outcome,
      classification: levelInfo.classification,
      riskLevel: levelInfo.riskLevel,
      severity: levelInfo.severity,
      verificationFailed: Boolean(levelInfo.verificationFailed),
      indicators: rules,
      rules,
      ruleSummary: {
        ...summarizeRules(rules),
        pipelineStagesExecuted: evaluated.pipelineStagesExecuted || [],
      },
      significantCategoryCount,
      categoryScores: cappedBreakdown,
      synergyAdded,
      overrideApplied,
      configUsed: config,
    };
  }

  return {
    OUTCOMES,
    DEFAULT_CONFIG,
    classifyScore,
    scoreFeatures,
  };
});
