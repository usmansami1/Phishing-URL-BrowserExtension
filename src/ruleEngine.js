/**
 * PhishGuard - Comprehensive Rule Evaluation Engine
 * Evaluates extracted URL, host, brand, keyword, path, redirect, protocol,
 * reputation, and multi-indicator combination rules with graduated thresholds
 * and full rule-level explainability metadata.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  }
  root.PhishGuardRuleEngine = api;
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

  const CATEGORY_LABELS = {
    urlComplexity: 'URL Length & Complexity',
    charManipulation: 'Characters & Obfuscation',
    hostStructure: 'Domain & Host Structure',
    brandImpersonation: 'Structural Mimicry & Lookalikes',
    lureKeywords: 'Suspicious Keywords & Intent',
    pathAndQuery: 'Path & Query Manipulation',
    redirectPatterns: 'Redirect & Parameter Patterns',
    transportAndProtocol: 'Protocol & Port Context',
    domainReputation: 'TLD & Domain Reputation',
    indicatorCombinations: 'Multi-Indicator Combinations',
    pageContext: 'Webpage Context Signals',
    threatIntel: 'Verified Threat Intelligence',
  };

  const DEFAULT_RULE_THRESHOLDS = {
    urlLengthModerate: 101,
    urlLengthLong: 160,
    urlLengthExcessive: 250,
    domainLengthLong: 36,
    domainLengthExtreme: 55,
    subdomainSectionLong: 30,
    subdomainLabelExtreme: 28,
    domainLabelLong: 28,
    domainLabelExtreme: 40,
    pathLengthLong: 85,
    pathLengthExcessive: 140,
    pathSegmentsDeep: 5,
    pathSegmentsExcessive: 7,
    queryParamsMany: 6,
    queryParamsExcessive: 10,
    queryParamValueLong: 90,
    queryParamValueExtreme: 150,
    longFragmentChars: 60,
    dotCountElevated: 4,
    dotCountTotalElevated: 6,
    dotCountHigh: 6,
    dotCountTotalHigh: 9,
    hostHyphensTwo: 2,
    hostHyphensThree: 3,
    hostHyphensFourPlus: 4,
    urlDigitsModerate: 18,
    urlDigitsHigh: 32,
    specialCharRatioElevated: 0.14,
    specialCharRatioHigh: 0.22,
    punctuationDensityHigh: 0.28,
    nonSpaceEncodedExcessive: 6,
    nonSpaceEncodedHeavy: 15,
    subdomainsTwo: 2,
    subdomainsThreeFour: 3,
    subdomainsFivePlus: 5,
    newlyRegisteredDays: 90,
    veryRecentDays: 14,
  };

  function makeRule(spec) {
    return {
      ruleId: spec.ruleId,
      ruleName: spec.ruleName,
      category: spec.category,
      categoryLabel: CATEGORY_LABELS[spec.category] || spec.category,
      severity: spec.severity || 'low',
      indicatorStrength: spec.indicatorStrength || 'weak',
      explanation: spec.explanation,
      evidence: spec.evidence,
      weight: Number(spec.weight) || 0,
      statusText:
        spec.statusText ||
        (spec.severity === 'high'
          ? 'Detected'
          : spec.severity === 'medium'
            ? 'Flagged'
            : 'Noted'),
      // UI-compatible presentation fields (keep labels clear and jargon-free)
      id: spec.ruleId,
      label: spec.label,
      detail: `${spec.explanation} Evidence: ${spec.evidence}`,
    };
  }

  const REGISTERED_PIPELINE_STAGES = [
    { stageId: 'url_complexity', category: 'urlComplexity', name: 'URL Length & Complexity Rules' },
    { stageId: 'char_manipulation', category: 'charManipulation', name: 'Character Manipulation & Obfuscation Rules' },
    { stageId: 'host_structure', category: 'hostStructure', name: 'Domain & Hostname Structure Rules' },
    { stageId: 'brand_impersonation', category: 'brandImpersonation', name: 'Structural Mimicry & Lookalike Pattern Rules' },
    { stageId: 'lure_keywords', category: 'lureKeywords', name: 'Suspicious Keywords & Lure Intent Rules' },
    { stageId: 'path_and_query', category: 'pathAndQuery', name: 'Path, Filename & Query Manipulation Rules' },
    { stageId: 'redirect_patterns', category: 'redirectPatterns', name: 'Redirect & Parameter Pattern Rules' },
    { stageId: 'transport_protocol', category: 'transportAndProtocol', name: 'Protocol, Port & Transport Rules' },
    { stageId: 'domain_reputation', category: 'domainReputation', name: 'TLD & Domain Reputation Rules' },
    { stageId: 'page_context', category: 'pageContext', name: 'DOM Page Context Rules' },
    { stageId: 'indicator_combinations', category: 'indicatorCombinations', name: 'Correlated Multi-Indicator Rules' },
  ];

  function createRuleContext(features, context, customConfig) {
    const cfg = customConfig || {};
    const th = { ...DEFAULT_RULE_THRESHOLDS, ...(cfg.ruleThresholds || {}) };
    const w = cfg.weights || {};
    const rules = [];
    const triggeredIds = new Set();
    const pageSignals = context && context.pageSignals ? context.pageSignals : null;
    const regInfo = context && context.registrationInfo ? context.registrationInfo : null;

    const { structure, domain, patterns } = features;
    const pq = patterns.pathAndQuery || {};
    const kw = patterns.keywords || {};
    const scriptInfo = domain.scriptInfo || {};

    const push = (spec) => {
      if (!spec || !spec.ruleId) return;
      const rule = makeRule(spec);
      rules.push(rule);
      triggeredIds.add(rule.ruleId);
    };

    return {
      features,
      parsedUrl: features.normalizedUrl,
      rawUrl: features.rawUrl,
      structure,
      domain,
      patterns,
      pq,
      kw,
      scriptInfo,
      pageSignals,
      regInfo,
      th,
      w,
      rules,
      triggeredIds,
      push,
    };
  }

  function evaluateCategoryA_UrlComplexity(ctx) {
    const { features, structure, domain, th, w, push } = ctx;
    // =========================================================================
    // CATEGORY A: URL Length & Complexity (Graduated Ladders)
    // =========================================================================
      if (structure.urlLength >= th.urlLengthExcessive) {
        push({
          ruleId: 'url_length_excessive',
          ruleName: 'Excessively Long URL',
          category: 'urlComplexity',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.urlLengthExcessive ?? 9,
          statusText: 'Flagged',
          label: `Excessively long URL structure (${structure.urlLength} characters)`,
          explanation: 'Very long URLs are commonly used to push deceptive domains out of view or conceal redirect parameters.',
          evidence: `Total URL length is ${structure.urlLength} characters.`,
        });
      } else if (structure.urlLength >= th.urlLengthLong) {
        push({
          ruleId: 'url_length_long',
          ruleName: 'Very Long URL',
          category: 'urlComplexity',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.veryLongUrl ?? 6,
          label: `Extended URL length (${structure.urlLength} characters)`,
          explanation: 'URL length exceeds typical navigation links and warrants reviewing destination parameters.',
          evidence: `Total URL length is ${structure.urlLength} characters.`,
        });
      } else if (structure.urlLength >= th.urlLengthModerate) {
        push({
          ruleId: 'url_length_moderate',
          ruleName: 'Moderately Long URL',
          category: 'urlComplexity',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.unusuallyLongUrl ?? 3,
          label: `Long URL (${structure.urlLength} characters)`,
          explanation: 'URL is moderately longer than typical concise domain paths.',
          evidence: `Total URL length is ${structure.urlLength} characters.`,
        });
      }

      if (structure.domainLength >= th.domainLengthExtreme) {
        push({
          ruleId: 'domain_length_extreme',
          ruleName: 'Extremely Long Domain Name',
          category: 'urlComplexity',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.domainLengthExtreme ?? 9,
          statusText: 'Flagged',
          label: `Extremely long hostname (${structure.domainLength} characters)`,
          explanation: 'Overly long hostnames can obscure the real registered domain behind descriptive lure words.',
          evidence: `Hostname "${features.hostname}" is ${structure.domainLength} characters long.`,
        });
      } else if (structure.domainLength >= th.domainLengthLong) {
        push({
          ruleId: 'domain_length_long',
          ruleName: 'Long Domain Name',
          category: 'urlComplexity',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.longHostname ?? 4,
          label: `Long domain name (${structure.domainLength} characters)`,
          explanation: 'Hostname length is longer than usual.',
          evidence: `Hostname "${features.hostname}" measures ${structure.domainLength} characters.`,
        });
      }

      if (structure.maxSubdomainLabelLength >= th.subdomainLabelExtreme) {
        push({
          ruleId: 'subdomain_label_extreme',
          ruleName: 'Extremely Long Subdomain Label',
          category: 'urlComplexity',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.subdomainLabelExtreme ?? 8,
          statusText: 'Flagged',
          label: 'Unusually long subdomain label in hostname',
          explanation: 'Very long subdomain labels can make mobile or narrow address bars clip the true registered domain.',
          evidence: `Longest subdomain label contains ${structure.maxSubdomainLabelLength} characters.`,
        });
      } else if (structure.subdomainStrLength >= th.subdomainSectionLong) {
        push({
          ruleId: 'subdomain_section_long',
          ruleName: 'Long Subdomain Section',
          category: 'urlComplexity',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.subdomainSectionLong ?? 4,
          label: 'Extended subdomain prefix section',
          explanation: 'Subdomain prefix is unusually long compared to the base domain.',
          evidence: `Subdomain string measures ${structure.subdomainStrLength} characters.`,
        });
      }

      if (structure.pathLength >= th.pathLengthExcessive) {
        push({
          ruleId: 'path_length_excessive',
          ruleName: 'Excessive URL Path Length',
          category: 'urlComplexity',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.pathLengthExcessive ?? 5,
          label: `Excessive URL path length (${structure.pathLength} chars)`,
          explanation: 'Long path strings may embed fake folders mimicking legitimate site hierarchies.',
          evidence: `URL path length is ${structure.pathLength} characters.`,
        });
      } else if (structure.pathLength >= th.pathLengthLong) {
        push({
          ruleId: 'path_length_long',
          ruleName: 'Long URL Path',
          category: 'urlComplexity',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.pathLengthLong ?? 3,
          label: `Long URL path (${structure.pathLength} chars)`,
          explanation: 'URL path is longer than typical landing pages.',
          evidence: `URL path length is ${structure.pathLength} characters.`,
        });
      }

      if (structure.pathSegmentCount >= th.pathSegmentsExcessive) {
        push({
          ruleId: 'path_segments_excessive',
          ruleName: 'Excessively Deep URL Path',
          category: 'urlComplexity',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.pathSegmentsExcessive ?? 6,
          statusText: 'Flagged',
          label: `Deeply nested URL path (${structure.pathSegmentCount} folders)`,
          explanation: 'Deeply nested paths are often generated by automated phishing kits or redirect chains.',
          evidence: `Path has ${structure.pathSegmentCount} nested segments.`,
        });
      } else if (structure.pathSegmentCount >= th.pathSegmentsDeep) {
        push({
          ruleId: 'path_segments_deep',
          ruleName: 'Deep URL Path',
          category: 'urlComplexity',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.pathSegmentsDeep ?? 3,
          label: `Multiple nested path segments (${structure.pathSegmentCount})`,
          explanation: 'URL path traverses several nested segments.',
          evidence: `Detected ${structure.pathSegmentCount} path segments.`,
        });
      }

      if (structure.queryParamCount >= th.queryParamsExcessive) {
        push({
          ruleId: 'query_params_excessive',
          ruleName: 'Excessive Query Parameters',
          category: 'urlComplexity',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.queryParamsExcessive ?? 6,
          statusText: 'Flagged',
          label: `Excessive query parameters (${structure.queryParamCount})`,
          explanation: 'A high parameter count can conceal tracking blobs, encoded emails, or redirection tokens.',
          evidence: `Found ${structure.queryParamCount} query parameters.`,
        });
      } else if (structure.queryParamCount >= th.queryParamsMany) {
        push({
          ruleId: 'query_params_many',
          ruleName: 'Many Query Parameters',
          category: 'urlComplexity',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.queryParamsMany ?? 3,
          label: `High number of query parameters (${structure.queryParamCount})`,
          explanation: 'URL includes numerous query parameters.',
          evidence: `Detected ${structure.queryParamCount} query parameters.`,
        });
      }

      if (structure.maxQueryValueLength >= th.queryParamValueExtreme) {
        push({
          ruleId: 'query_param_value_extreme',
          ruleName: 'Extremely Long Query Parameter Value',
          category: 'urlComplexity',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.queryParamValueExtreme ?? 5,
          label: 'Unusually large query parameter value',
          explanation: 'Long parameter payloads often store serialized state, tracking tokens, or encoded destinations.',
          evidence: `Longest parameter value has ${structure.maxQueryValueLength} characters.`,
        });
      } else if (structure.maxQueryValueLength >= th.queryParamValueLong) {
        push({
          ruleId: 'query_param_value_long',
          ruleName: 'Long Query Parameter Value',
          category: 'urlComplexity',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.queryParamValueLong ?? 3,
          label: 'Long query parameter payload',
          explanation: 'One query parameter carries an extended data string.',
          evidence: `Longest parameter value has ${structure.maxQueryValueLength} characters.`,
        });
      }

      if (structure.fragmentCount >= 2) {
        push({
          ruleId: 'multiple_url_fragments',
          ruleName: 'Multiple URL Fragment Symbols',
          category: 'urlComplexity',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.multipleFragments ?? 8,
          statusText: 'Flagged',
          label: 'Multiple "#" fragment markers in URL',
          explanation: 'Multiple fragment symbols can confuse naive parsers or hide client-side routing payloads.',
          evidence: `Detected ${structure.fragmentCount} "#" fragment delimiters.`,
        });
      } else if (structure.fragmentLength >= th.longFragmentChars) {
        push({
          ruleId: 'long_url_fragment',
          ruleName: 'Unusually Long URL Fragment',
          category: 'urlComplexity',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.longFragment ?? 4,
          label: 'Long fragment payload after "#"',
          explanation: 'Long URL fragments can pass concealed client-side data such as pre-filled account details.',
          evidence: `Fragment section is ${structure.fragmentLength} characters long.`,
        });
      }

      if (!structure.hasIpAddress) {
        if (structure.dotCountInHost >= th.dotCountHigh || structure.dotCountTotal >= th.dotCountTotalHigh) {
          push({
            ruleId: 'excessive_dots_high',
            ruleName: 'Excessive Dot Count in URL',
            category: 'urlComplexity',
            severity: 'medium',
            indicatorStrength: 'medium',
            weight: w.excessiveDotsHigh ?? 8,
            statusText: 'Flagged',
            label: `Excessive dot delimiters (${structure.dotCountInHost} in host, ${structure.dotCountTotal} total)`,
            explanation: 'Many dots in a hostname or URL often signal multi-layer spoofing of trusted domain structures.',
            evidence: `${structure.dotCountInHost} dots in hostname; ${structure.dotCountTotal} dots in complete URL.`,
          });
        } else if (structure.dotCountInHost >= th.dotCountElevated || structure.dotCountTotal >= th.dotCountTotalElevated) {
          push({
            ruleId: 'elevated_dots',
            ruleName: 'Elevated Dot Count',
            category: 'urlComplexity',
            severity: 'low',
            indicatorStrength: 'weak',
            weight: w.elevatedDots ?? 3,
            label: `Elevated number of dots in URL (${structure.dotCountTotal})`,
            explanation: 'Higher dot frequency across hostname or path segments.',
            evidence: `${structure.dotCountInHost} dots in host, ${structure.dotCountTotal} total dots.`,
          });
        }
      }

      // Graduated Hyphen Ladder (1 hyphen = ignored; 2 weak; 3 medium; 4+ stronger medium)
      if (!domain.hasPunycode) {
        if (structure.hyphenCountInHost >= th.hostHyphensFourPlus) {
          push({
            ruleId: 'host_hyphens_four_plus',
            ruleName: 'Heavy Hyphenation in Domain',
            category: 'urlComplexity',
            severity: 'medium',
            indicatorStrength: 'medium',
            weight: w.hostHyphensFourPlus ?? 12,
            statusText: 'Flagged',
            label: `Heavy hyphenation in domain (${structure.hyphenCountInHost} hyphens)`,
            explanation: 'Four or more hyphens in a domain name strongly correlate with synthetic phishing lookalikes.',
            evidence: `Hostname contains ${structure.hyphenCountInHost} hyphens.`,
          });
        } else if (structure.hyphenCountInHost >= th.hostHyphensThree) {
          push({
            ruleId: 'host_hyphens_three',
            ruleName: 'Multiple Hyphens in Domain',
            category: 'urlComplexity',
            severity: 'low',
            indicatorStrength: 'weak',
            weight: w.hostHyphensThree ?? 4,
            statusText: 'Noted',
            label: `Multiple hyphens in domain (${structure.hyphenCountInHost} hyphens)`,
            explanation: 'Three hyphens in a domain can occur in legitimate multi-word domains and are treated as a weak signal unless paired with stronger indicators.',
            evidence: `Hostname contains ${structure.hyphenCountInHost} hyphens.`,
          });
        } else if (structure.hyphenCountInHost >= th.hostHyphensTwo) {
          push({
            ruleId: 'host_hyphens_two',
            ruleName: 'Moderate Hyphenation in Domain',
            category: 'urlComplexity',
            severity: 'low',
            indicatorStrength: 'weak',
            weight: w.hostHyphensTwo ?? 2,
            label: `Hyphenated hostname (${structure.hyphenCountInHost} hyphens)`,
            explanation: 'Two hyphens in the hostname noted as a weak structural indicator.',
            evidence: `Hostname contains ${structure.hyphenCountInHost} hyphens.`,
          });
        }
      }

      if (structure.underscoreCountInHost > 0) {
        push({
          ruleId: 'underscore_in_hostname',
          ruleName: 'Underscore in Hostname',
          category: 'urlComplexity',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.underscoreInHost ?? 9,
          statusText: 'Flagged',
          label: 'Non-standard underscore character in domain',
          explanation: 'Standard Internet domain names rarely use underscores, which can indicate misconfigured or deceptive hosts.',
          evidence: `Hostname contains ${structure.underscoreCountInHost} underscore(s).`,
        });
      } else if (structure.underscoreCountTotal >= 4) {
        push({
          ruleId: 'excessive_underscores_url',
          ruleName: 'Excessive Underscores in URL',
          category: 'urlComplexity',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.excessiveUnderscoresUrl ?? 3,
          label: `Frequent underscores in URL (${structure.underscoreCountTotal})`,
          explanation: 'Numerous underscores appear in URL path or query names.',
          evidence: `Detected ${structure.underscoreCountTotal} underscores in URL.`,
        });
      }

      if (!structure.hasIpAddress) {
        if (structure.digitCountUrl >= th.urlDigitsHigh) {
          push({
            ruleId: 'excessive_digits_high',
            ruleName: 'High Numeric Digit Count in URL',
            category: 'urlComplexity',
            severity: 'low',
            indicatorStrength: 'weak',
            weight: w.excessiveDigitsHigh ?? 5,
            label: `High number of digits in URL (${structure.digitCountUrl})`,
            explanation: 'Large blocks of digits can indicate generated campaign IDs or random infrastructure.',
            evidence: `URL contains ${structure.digitCountUrl} numeric digits.`,
          });
        } else if (structure.digitCountUrl >= th.urlDigitsModerate) {
          push({
            ruleId: 'excessive_digits_moderate',
            ruleName: 'Elevated Digit Count in URL',
            category: 'urlComplexity',
            severity: 'low',
            indicatorStrength: 'weak',
            weight: w.excessiveDigitsModerate ?? 2,
            label: `Elevated numeric digit count (${structure.digitCountUrl})`,
            explanation: 'Multiple numeric sequences appear across the URL.',
            evidence: `URL contains ${structure.digitCountUrl} numeric digits.`,
          });
        }

        if (structure.alnumTransitionsHost >= 4) {
          push({
            ruleId: 'alphanumeric_clutter_host',
            ruleName: 'Unusual Letter-Number Mixing in Domain',
            category: 'urlComplexity',
            severity: 'medium',
            indicatorStrength: 'medium',
            weight: w.alnumClutterHost ?? 9,
            statusText: 'Flagged',
            label: 'Unusual letter and number mixing inside domain',
            explanation: 'Frequent switching between letters and digits often reflects character substitution or generated domains.',
            evidence: `Detected ${structure.alnumTransitionsHost} letter-digit transitions inside hostname labels.`,
          });
        } else if (structure.alnumTransitionsHost >= 2) {
          push({
            ruleId: 'alphanumeric_mix_host',
            ruleName: 'Letter-Number Alternation in Domain',
            category: 'urlComplexity',
            severity: 'low',
            indicatorStrength: 'weak',
            weight: w.alnumMixHost ?? 4,
            label: 'Mixed letter and digit patterns inside domain',
            explanation: 'Hostname interleaves letters and digits within the same label.',
            evidence: `Detected ${structure.alnumTransitionsHost} letter-digit transitions in hostname.`,
          });
        }
      }

      if (structure.hasRepeatedSpecialChars) {
        push({
          ruleId: 'repeated_special_chars',
          ruleName: 'Repeated Special Characters',
          category: 'urlComplexity',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.repeatedSpecialChars ?? 5,
          label: 'Repeated punctuation or special characters in URL',
          explanation: 'Repeated delimiter sequences can appear in malformed or obfuscated links.',
          evidence: 'Consecutive special characters found in URL structure.',
        });
      }

      if (structure.urlLength >= 25) {
        if (structure.specialCharRatio >= th.specialCharRatioHigh) {
          push({
            ruleId: 'high_special_char_ratio',
            ruleName: 'High Special-Character Ratio',
            category: 'urlComplexity',
            severity: 'medium',
            indicatorStrength: 'medium',
            weight: w.highSpecialCharRatio ?? 7,
            statusText: 'Flagged',
            label: 'High special-character density in URL',
            explanation: 'An unusually large share of URL characters consists of delimiters and symbols.',
            evidence: `${structure.specialCharCount} special symbols (${Math.round(structure.specialCharRatio * 100)}% of URL).`,
          });
        } else if (structure.specialCharRatio >= th.specialCharRatioElevated) {
          push({
            ruleId: 'elevated_special_char_ratio',
            ruleName: 'Elevated Special-Character Ratio',
            category: 'urlComplexity',
            severity: 'low',
            indicatorStrength: 'weak',
            weight: w.elevatedSpecialCharRatio ?? 3,
            label: 'Elevated special-character count in URL',
            explanation: 'Higher proportion of URL symbols than average web pages.',
            evidence: `${structure.specialCharCount} special characters across ${structure.urlLength} chars.`,
          });
        }

        if (structure.punctuationDensity >= th.punctuationDensityHigh) {
          push({
            ruleId: 'high_punctuation_density',
            ruleName: 'High Punctuation Density',
            category: 'urlComplexity',
            severity: 'low',
            indicatorStrength: 'weak',
            weight: w.highPunctuationDensity ?? 4,
            label: 'Dense punctuation throughout URL',
            explanation: 'Punctuation marks make up a notably high fraction of the URL address.',
            evidence: `${structure.punctuationCount} punctuation characters detected.`,
          });
        }
      }

      if (!structure.hasIpAddress && structure.maxDomainLabelLength >= th.domainLabelExtreme) {
        push({
          ruleId: 'domain_label_extreme',
          ruleName: 'Excessively Long Domain Label',
          category: 'urlComplexity',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.domainLabelExtreme ?? 9,
          statusText: 'Flagged',
          label: `Excessively long domain label (${structure.maxDomainLabelLength} chars)`,
          explanation: 'A single very long DNS label is uncommon outside synthetic infrastructure or spoofing.',
          evidence: `Longest domain label is ${structure.maxDomainLabelLength} characters.`,
        });
      } else if (!structure.hasIpAddress && structure.maxDomainLabelLength >= th.domainLabelLong) {
        push({
          ruleId: 'domain_label_long',
          ruleName: 'Long Domain Label',
          category: 'urlComplexity',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.domainLabelLong ?? 4,
          label: `Long individual domain label (${structure.maxDomainLabelLength} chars)`,
          explanation: 'Hostname includes an unusually wide single label.',
          evidence: `Longest domain label is ${structure.maxDomainLabelLength} characters.`,
        });
      }

      if (structure.hasConsecutiveSeparators && !domain.hasPunycode) {
        push({
          ruleId: 'consecutive_separators',
          ruleName: 'Consecutive Separators in URL',
          category: 'urlComplexity',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.consecutiveSeparators ?? 8,
          statusText: 'Flagged',
          label: 'Consecutive hyphens, underscores, or dots detected',
          explanation: 'Repeated separator sequences like "--" or ".." can attempt visual or parser deception.',
          evidence: 'Repeated separator pattern detected in hostname or path.',
        });
      }

      if (structure.hostRepeatedChar || structure.pathRepeatedChar) {
        push({
          ruleId: 'repeated_char_sequences',
          ruleName: 'Repeated Character Sequences',
          category: 'urlComplexity',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.repeatedCharSequences ?? 4,
          label: 'Repeated character patterns detected',
          explanation: 'Long runs of identical characters appear in the hostname or path.',
          evidence: structure.hostRepeatedChar
            ? `Hostname "${features.hostname}" contains repeated character runs.`
            : 'Path contains extended repeated character sequences.',
        });
      }

      if (domain.hasRandomLookingDomain) {
        push({
          ruleId: 'domain_high_entropy',
          ruleName: 'High-Randomness Registered Domain',
          category: 'urlComplexity',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.domainHighEntropy ?? 12,
          statusText: 'Flagged',
          label: `Random-looking registered domain (${domain.registrableDomain})`,
          explanation: 'High character randomness or scarce vowels suggest an automatically generated domain.',
          evidence: `Registered domain label "${domain.sld}" has elevated entropy and irregular letter distribution.`,
        });
      }
  }

  function evaluateCategoryB_CharManipulation(ctx) {
    const { features, structure, domain, patterns, kw, scriptInfo, th, w, push } = ctx;
    // =========================================================================
    // CATEGORY B: Suspicious Characters & URL Manipulation
    // =========================================================================
    if (patterns.hasAtInAuthority) {
      push({
        ruleId: 'at_in_authority',
        ruleName: 'Authority "@" Redirection Deception',
        category: 'charManipulation',
        severity: 'high',
        indicatorStrength: 'strong',
        weight: w.atInAuthority ?? 34,
        statusText: 'Detected',
        label: 'Deceptive "@" symbol in URL authority',
        explanation: 'Text before "@" is treated as username metadata while the browser actually connects to the host after "@".',
        evidence: `Authority section embeds "@" before connecting to "${features.hostname}".`,
      });
    }

    if (patterns.hasMultipleAt) {
      push({
        ruleId: 'multiple_at_symbols',
        ruleName: 'Multiple "@" Symbols in URL',
        category: 'charManipulation',
        severity: 'high',
        indicatorStrength: 'strong',
        weight: w.multipleAtSymbols ?? 16,
        statusText: 'Detected',
        label: `Multiple "@" symbols in URL (${patterns.atCount})`,
        explanation: 'Multiple "@" symbols are rarely valid in URLs and frequently indicate obfuscation or multi-stage deception.',
        evidence: `Detected ${patterns.atCount} "@" characters in submitted URL.`,
      });
    }

    if (patterns.hasEncodedAt) {
      push({
        ruleId: 'encoded_at_symbol',
        ruleName: 'Percent-Encoded "@" Symbol',
        category: 'charManipulation',
        severity: 'high',
        indicatorStrength: 'strong',
        weight: w.encodedAtSymbol ?? 18,
        statusText: 'Flagged',
        label: 'Percent-encoded "@" symbol (%40) in URL',
        explanation: 'Encoding "@" as %40 is a known technique to bypass simple "@" checks.',
        evidence: 'Found "%40" sequence inside the URL.',
      });
    }

    if (patterns.hasHexEscapeInAuthority) {
      push({
        ruleId: 'hex_in_authority',
        ruleName: 'Percent-Encoded Hostname Bytes',
        category: 'charManipulation',
        severity: 'high',
        indicatorStrength: 'strong',
        weight: w.hexEscapeInAuthority ?? 18,
        statusText: 'Flagged',
        label: 'Encoded hexadecimal characters in URL host',
        explanation: 'Hexadecimal escapes in the hostname can obscure the true destination server.',
        evidence: 'Percent-encoded byte sequences appear inside host authority.',
      });
    }

    if (patterns.hasDoubleEncoding) {
      push({
        ruleId: 'double_encoding',
        ruleName: 'Double Percent Encoding',
        category: 'charManipulation',
        severity: 'medium',
        indicatorStrength: 'strong',
        weight: w.doublePercentEncoding ?? 16,
        statusText: 'Flagged',
        label: 'Double percent-encoded URL sequences',
        explanation: 'Repeated percent encoding (%25xx) is commonly used to evade URL scanners and security filters.',
        evidence: 'Nested "%25" hexadecimal encoding detected in URL.',
      });
    }

      const hasSuspiciousEncodedDelimiter =
        patterns.hasEncodedDotOrSlashInPath !== undefined
          ? patterns.hasEncodedDotOrSlashInPath
          : (patterns.hasEncodedDot || patterns.hasEncodedSlash);

      if (hasSuspiciousEncodedDelimiter) {
        push({
          ruleId: 'encoded_dots_or_slashes',
          ruleName: 'Percent-Encoded Dots or Slashes',
          category: 'charManipulation',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.encodedDotsOrSlashes ?? 10,
          statusText: 'Flagged',
          label: 'Encoded dots or slashes inside URL path/authority',
          explanation: 'Percent-encoding "." or "/" in URL paths or authority is frequently used to conceal redirects or path traversal tricks.',
          evidence: `Encoded path/delimiter bytes found (${patterns.hasEncodedSlash ? '%2f' : ''}${patterns.hasEncodedSlash && patterns.hasEncodedDot ? ' & ' : ''}${patterns.hasEncodedDot ? '%2e' : ''}).`,
        });
      }

      if (patterns.nonSpaceEncodedCount >= th.nonSpaceEncodedHeavy) {
        push({
          ruleId: 'heavy_percent_encoding',
          ruleName: 'Heavy Percent Encoding',
          category: 'charManipulation',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.heavyPercentEncoding ?? 12,
          statusText: 'Flagged',
          label: `Heavy hexadecimal percent encoding (${patterns.percentEncodedCount} sequences)`,
          explanation: 'Extensive encoding masks readable paths or embedded destination addresses.',
          evidence: `Detected ${patterns.nonSpaceEncodedCount} non-space percent-encoded bytes.`,
        });
      } else if (patterns.nonSpaceEncodedCount >= th.nonSpaceEncodedExcessive) {
        push({
          ruleId: 'excessive_percent_encoding',
          ruleName: 'Excessive Percent Encoding',
          category: 'charManipulation',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.excessivePercentEncoding ?? 7,
          label: `Multiple percent-encoded sequences (${patterns.percentEncodedCount})`,
          explanation: 'Substantial URL encoding reduces readability of destination components.',
          evidence: `Detected ${patterns.nonSpaceEncodedCount} non-space percent-encoded sequences.`,
        });
      } else if (patterns.nonSpaceEncodedCount >= 2) {
        push({
          ruleId: 'percent_encoding_present',
          ruleName: 'Percent-Encoded URL Sequences',
          category: 'charManipulation',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.percentEncodingPresent ?? 2,
          label: `Percent-encoded sequences present (${patterns.nonSpaceEncodedCount})`,
          explanation: 'URL uses percent-encoded byte values; common in parameters unless masking malicious values.',
          evidence: `Detected ${patterns.nonSpaceEncodedCount} non-space percent-encoded sequence(s).`,
        });
      }

      if (patterns.hasHexSequences && !patterns.hasHexEscapeInAuthority) {
        push({
          ruleId: 'hex_sequences',
          ruleName: 'Hexadecimal-Style Sequences in URL',
          category: 'charManipulation',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.hexSequences ?? 6,
          label: 'Hexadecimal-looking sequence in URL',
          explanation: 'Long hexadecimal sequences or 0x notation can obscure IP hosts or encoded payloads.',
          evidence: 'Detected long hexadecimal or 0x-prefixed sequence.',
        });
      }

    if (domain.hasPunycode) {
      push({
        ruleId: 'punycode_idn',
        ruleName: 'Punycode Domain Prefix (xn--)',
        category: 'charManipulation',
        severity: domain.hasConfusableCharsInHost ? 'medium' : 'low',
        indicatorStrength: domain.hasConfusableCharsInHost ? 'medium' : 'weak',
        weight: w.punycodeIdn ?? 12,
        statusText: domain.hasConfusableCharsInHost ? 'Flagged' : 'Noted',
        label: 'Punycode internationalized domain name ("xn--")',
        explanation: 'Punycode ("xn--") domains can host legitimate international text or imitate ASCII lookalikes visually.',
        evidence: `Hostname contains Punycode label; decoded representation: "${domain.decodedHost || features.hostname}".`,
      });
    } else if (domain.rawHostHasNonAscii) {
      push({
        ruleId: 'unicode_domain_chars',
        ruleName: 'Non-ASCII Unicode Characters in Domain',
        category: 'charManipulation',
        severity: domain.hasConfusableCharsInHost ? 'medium' : 'low',
        indicatorStrength: domain.hasConfusableCharsInHost ? 'medium' : 'weak',
        weight: w.punycodeIdn ?? 12,
        statusText: domain.hasConfusableCharsInHost ? 'Flagged' : 'Noted',
        label: 'International Unicode characters in domain name',
        explanation: 'Non-ASCII hostname characters may represent an internationalized domain or visually spoof standard letters.',
        evidence: `Raw hostname "${features.rawAuthorityInfo.rawHost}" includes non-ASCII characters.`,
      });
    }

    if (scriptInfo.hasMixedScriptsInLabel) {
      push({
        ruleId: 'mixed_scripts_in_domain',
        ruleName: 'Mixed Unicode Scripts in Single Domain Label',
        category: 'charManipulation',
        severity: 'high',
        indicatorStrength: 'strong',
        weight: w.mixedScriptsInDomain ?? 34,
        statusText: 'Detected',
        label: 'Mixed writing scripts inside a single domain label',
        explanation: 'Combining different alphabets (such as Latin with Cyrillic or Greek) inside one domain label is a hallmark IDN homograph attack.',
        evidence: `Domain label mixes scripts: ${scriptInfo.scripts.join(' + ')}.`,
      });
    } else if (domain.hasConfusableCharsInHost) {
      push({
        ruleId: 'confusable_unicode_chars',
        ruleName: 'Visually Confusable Unicode Characters',
        category: 'charManipulation',
        severity: 'medium',
        indicatorStrength: 'medium',
        weight: w.confusableUnicodeChars ?? 18,
        statusText: 'Flagged',
        label: 'Hostname contains visually confusable Unicode characters',
        explanation: 'Domain contains Unicode characters visually resembling standard Latin letters.',
        evidence: `Decoded host "${domain.decodedHost || features.hostname}" uses non-Latin lookalikes.`,
      });
    }

    if (patterns.hasBidiChars) {
      push({
        ruleId: 'bidi_unicode_chars',
        ruleName: 'Bidirectional Text Control Characters',
        category: 'charManipulation',
        severity: 'high',
        indicatorStrength: 'strong',
        weight: w.bidiUnicodeChars ?? 42,
        statusText: 'Detected',
        label: 'Hidden bidirectional (RTL/LTR) control characters in URL',
        explanation: 'Bidirectional override controls can reverse displayed text order to disguise filenames or hosts.',
        evidence: 'Detected Unicode bidirectional control code point in URL.',
      });
    }

    if (patterns.hasInvisibleUnicode) {
      push({
        ruleId: 'invisible_unicode_chars',
        ruleName: 'Zero-Width or Invisible Unicode Characters',
        category: 'charManipulation',
        severity: 'high',
        indicatorStrength: 'strong',
        weight: w.invisibleUnicodeChars ?? 36,
        statusText: 'Detected',
        label: 'Invisible or zero-width Unicode characters in URL',
        explanation: 'Zero-width characters can make a deceptive domain or path appear identical to a trusted address.',
        evidence: 'Detected invisible/zero-width Unicode code point.',
      });
    }

    if (patterns.hasTilde) {
      push({
        ruleId: 'unusual_tilde',
        ruleName: 'Tilde Character in URL',
        category: 'charManipulation',
        severity: 'low',
        indicatorStrength: 'weak',
        weight: w.unusualTilde ?? 5,
        label: 'Unusual "~" user-directory marker in URL',
        explanation: 'Tilde paths (~user) sometimes point to shared web directories misused for phishing pages.',
        evidence: 'Found "~" character inside URL.',
      });
    }

    if (patterns.hasBackslashInAuthority) {
      push({
        ruleId: 'backslash_in_authority',
        ruleName: 'Backslash in URL Authority',
        category: 'charManipulation',
        severity: 'high',
        indicatorStrength: 'strong',
        weight: w.backslashInAuthority ?? 28,
        statusText: 'Detected',
        label: 'Backslash ("\\") manipulation in URL host',
        explanation: 'Backslashes inside the authority section can cause parser confusion between decoy and destination hosts.',
        evidence: 'Found backslash or "%5c" inside URL authority.',
      });
    } else if (patterns.hasBackslash) {
      push({
        ruleId: 'backslash_in_url',
        ruleName: 'Backslash Character in URL',
        category: 'charManipulation',
        severity: 'medium',
        indicatorStrength: 'medium',
        weight: w.backslashInUrl ?? 12,
        statusText: 'Flagged',
        label: 'Backslash ("\\") character present in URL',
        explanation: 'Standard web URLs use forward slashes; backslashes can alter path interpretation.',
        evidence: 'Backslash or "%5c" detected in URL.',
      });
    }

    if (patterns.hasDoubleSlashAfterHost) {
      push({
        ruleId: 'multiple_slashes_path',
        ruleName: 'Multiple Consecutive Slashes After Hostname',
        category: 'charManipulation',
        severity: 'medium',
        indicatorStrength: 'medium',
        weight: w.multipleSlashesAfterHost ?? 9,
        statusText: 'Flagged',
        label: 'Unusual consecutive slashes ("//") after hostname',
        explanation: 'Extra slashes after the domain name can trigger path confusion or open-redirect routing.',
        evidence: 'Detected "//" sequence inside URL path after authority.',
      });
    }

    if (kw.obfuscatedDomainLures && kw.obfuscatedDomainLures.length > 0) {
      const sample = kw.obfuscatedDomainLures[0];
      push({
        ruleId: 'obfuscated_lure_keyword',
        ruleName: 'Character-Substituted Security Keyword',
        category: 'charManipulation',
        severity: 'medium',
        indicatorStrength: 'strong',
        weight: w.obfuscatedLureKeyword ?? 34,
        statusText: 'Flagged',
        label: `Obfuscated keyword in domain ("${sample.rawToken}" mimics "${sample.normalizedWord}")`,
        explanation: 'Letters replaced by digits (e.g. "0" for "o", "1" for "l") disguise deceptive security keywords.',
        evidence: `Domain token "${sample.rawToken}" normalizes to "${sample.normalizedWord}".`,
      });
    }

    const uncoveredMedialMatches = (
      (domain.medialDigitSubstitutions && domain.medialDigitSubstitutions.matches) ||
      []
    ).filter(
      (m) => !(kw.obfuscatedDomainLures || []).some((o) => o.rawToken === m.token)
    );

    if (uncoveredMedialMatches.length > 0 && !structure.hasIpAddress) {
      const sample = uncoveredMedialMatches[0];
      const firstSub = sample.substitutions[0];
      push({
        ruleId: 'medial_digit_substitution',
        ruleName: 'Mid-Word Lookalike Digit Substitution',
        category: 'charManipulation',
        severity: 'medium',
        indicatorStrength: 'strong',
        weight: w.medialDigitSubstitution ?? 32,
        statusText: 'Flagged',
        label: `Mid-word lookalike digit substitution ("${sample.token}")`,
        explanation: 'Embedding lookalike digits (0, 1, 3, 4, 5) between letters inside a domain word commonly visually mimics standard alphabetic spellings.',
        evidence: `Token "${sample.token}" embeds "${firstSub.digits}" (visually resembles "${firstSub.letterHint}") between "${firstSub.leftLetters}" and "${firstSub.rightLetters}".`,
      });
    } else {
      const uncoveredBoundaryMatches = (
        (domain.boundaryDigitSubstitutions && domain.boundaryDigitSubstitutions.matches) ||
        []
      ).filter(
        (m) => !(kw.obfuscatedDomainLures || []).some((o) => o.rawToken === m.token)
      );

      if (uncoveredBoundaryMatches.length > 0 && !structure.hasIpAddress) {
        const sample = uncoveredBoundaryMatches[0];
        push({
          ruleId: 'boundary_digit_substitution',
          ruleName: 'Word-Boundary Lookalike Digit Substitution',
          category: 'charManipulation',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.boundaryDigitSubstitution ?? 30,
          statusText: 'Flagged',
          label: `Lookalike digit "${sample.digits}" attached to domain word ("${sample.token}")`,
          explanation: 'Attaching a visual lookalike digit (such as "1" for "l/i" or "0" for "o") to the boundary of an alphabetic hostname stem is a common typo/homoglyph substitution technique.',
          evidence: `Token "${sample.token}" pairs stem "${sample.stem}" with ${sample.position} digit "${sample.digits}" (resembles "${sample.letterHint}").`,
        });
      }
    }

    if (patterns.hasDomainShapedUserinfo) {
      push({
        ruleId: 'domain_shaped_userinfo',
        ruleName: 'Domain-Formatted Credentials Section Before "@"',
        category: 'charManipulation',
        severity: 'high',
        indicatorStrength: 'strong',
        weight: w.domainShapedUserinfo ?? 14,
        statusText: 'Detected',
        label: 'Decoy domain-like string placed before "@" in authority',
        explanation: 'Placing a hostname-like string inside the username portion before "@" misleads readers about which domain the browser actually connects to.',
        evidence: `Authority userinfo mimics a domain name before redirecting connection to "${features.hostname}".`,
      });
    }

  }

  function evaluateCategoryC_HostStructure(ctx) {
    const { features, structure, domain, patterns, pq, th, w, push } = ctx;
    // =========================================================================
    // CATEGORY C: Domain & Hostname Structure
    // =========================================================================
    if (structure.hasObfuscatedIp) {
      push({
        ruleId: 'obfuscated_ip',
        ruleName: 'Obfuscated Numeric/Hex/Octal IP Host',
        category: 'hostStructure',
        severity: 'high',
        indicatorStrength: 'strong',
        weight: w.obfuscatedIpAddress ?? 34,
        statusText: 'Detected',
        label: 'Obfuscated IP address used as host',
        explanation: 'Uses decimal, hexadecimal, or octal IP notation instead of a registered domain name.',
        evidence: `Raw authority "${features.rawAuthorityInfo.rawHost}" resolves to "${features.hostname}".`,
      });
    } else if (structure.isPublicIp && structure.isIPv6) {
      push({
        ruleId: 'ip_ipv6',
        ruleName: 'Direct IPv6 Address Host',
        category: 'hostStructure',
        severity: 'high',
        indicatorStrength: 'strong',
        weight: w.publicIpAddress ?? 30,
        statusText: 'Flagged',
        label: 'Direct IPv6 address instead of domain name',
        explanation: 'Legitimate consumer sites rarely ask users to browse directly via raw IPv6 literals.',
        evidence: `Host connects directly to IPv6 address ${features.hostname}.`,
      });
    } else if (structure.isPublicIp) {
      push({
        ruleId: 'ip_ipv4',
        ruleName: 'Direct IPv4 Address Host',
        category: 'hostStructure',
        severity: 'high',
        indicatorStrength: 'strong',
        weight: w.publicIpAddress ?? 30,
        statusText: 'Flagged',
        label: 'Raw IPv4 address instead of domain name',
        explanation: 'Using a raw IPv4 address bypasses domain identity transparency.',
        evidence: `Website is served directly from IP address ${features.hostname}.`,
      });
    } else if (structure.isPrivateOrLocalIp) {
      const hasUnexpectedContext =
        patterns.hasAtInAuthority ||
        domain.hasEmbeddedDomainInSubdomain ||
        pq.externalRedirectParams.length > 0;
      push({
        ruleId: 'localhost_or_private_ip',
        ruleName: 'Localhost or Private Network Address',
        category: 'hostStructure',
        severity: hasUnexpectedContext ? 'high' : 'low',
        indicatorStrength: hasUnexpectedContext ? 'strong' : 'weak',
        weight: hasUnexpectedContext ? (w.privateIpUnexpected ?? 28) : (w.privateIpBaseline ?? 2),
        statusText: hasUnexpectedContext ? 'Flagged' : 'Noted',
        label: hasUnexpectedContext
          ? 'Local/private IP address paired with deceptive indicators'
          : 'Local or private network address',
        explanation: hasUnexpectedContext
          ? 'Private or loopback host combined with misleading authority or brand cues.'
          : 'URL points to a local or private network address rather than a public website.',
        evidence: `Hostname resolves to local/private target "${features.hostname}".`,
      });
    }

    // Graduated Subdomain Nesting (1 = normal, 2 = weak, 3-4 = medium, 5+ = stronger warning)
    if (!structure.hasIpAddress) {
      if (structure.nonWwwSubdomainCount >= th.subdomainsFivePlus) {
        push({
          ruleId: 'subdomains_five_plus',
          ruleName: 'Heavy Subdomain Nesting (5+ Levels)',
          category: 'hostStructure',
          severity: 'high',
          indicatorStrength: 'strong',
          weight: w.subdomainsFivePlus ?? 22,
          statusText: 'Flagged',
          label: `Heavy subdomain nesting (${structure.nonWwwSubdomainCount} subdomain levels)`,
          explanation: 'Five or more subdomain levels strongly obscure which registered domain owns the page.',
          evidence: `Detected ${structure.nonWwwSubdomainCount} non-www subdomain levels before "${domain.registrableDomain}".`,
        });
      } else if (structure.nonWwwSubdomainCount >= th.subdomainsThreeFour) {
        push({
          ruleId: 'subdomains_three_four',
          ruleName: 'Excessive Subdomain Nesting (3–4 Levels)',
          category: 'hostStructure',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.subdomainsThreeFour ?? 12,
          statusText: 'Flagged',
          label: `Excessive subdomain nesting (${structure.nonWwwSubdomainCount} levels)`,
          explanation: 'Multiple nested subdomains can push misleading words into the visible part of the address bar.',
          evidence: `Detected ${structure.nonWwwSubdomainCount} non-www subdomain levels (${features.domainParts.subdomainStr}).`,
        });
      } else if (structure.nonWwwSubdomainCount >= th.subdomainsTwo) {
        push({
          ruleId: 'subdomains_two',
          ruleName: 'Two Non-WWW Subdomains',
          category: 'hostStructure',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.subdomainsTwo ?? 2,
          label: `Multi-level subdomain structure (${structure.nonWwwSubdomainCount} levels)`,
          explanation: 'Two subdomain levels observed; normal on many cloud services unless combined with other signals.',
          evidence: `Subdomains: ${features.domainParts.subdomainStr}.`,
        });
      }
    }

      if (domain.repeatedDomainLabels && domain.repeatedDomainLabels.length > 0) {
        push({
          ruleId: 'repeated_domain_labels',
          ruleName: 'Repeated Domain Labels',
          category: 'hostStructure',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.repeatedDomainLabels ?? 10,
          statusText: 'Flagged',
          label: `Repeated hostname label ("${domain.repeatedDomainLabels[0]}")`,
          explanation: 'Repeating identical words across subdomains often signals artificial or auto-generated phishing hosts.',
          evidence: `Label "${domain.repeatedDomainLabels[0]}" appears multiple times in hostname.`,
        });
      }

      if (domain.suspiciousDomainPrefixes && domain.suspiciousDomainPrefixes.length > 0) {
        push({
          ruleId: 'suspicious_domain_prefix',
          ruleName: 'Suspicious Domain Prefix',
          category: 'hostStructure',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.suspiciousDomainPrefix ?? 10,
          statusText: 'Flagged',
          label: `Suspicious domain prefix (${domain.suspiciousDomainPrefixes.join(', ')})`,
          explanation: 'Phishing domains frequently start with trust-implying prefixes like "secure-", "login-", or "verify-".',
          evidence: `Host label starts with prefix "${domain.suspiciousDomainPrefixes[0]}".`,
        });
      }

      if (domain.suspiciousDomainSuffixes && domain.suspiciousDomainSuffixes.length > 0) {
        push({
          ruleId: 'suspicious_domain_suffix',
          ruleName: 'Suspicious Domain Suffix',
          category: 'hostStructure',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.suspiciousDomainSuffix ?? 9,
          statusText: 'Flagged',
          label: `Suspicious domain suffix (${domain.suspiciousDomainSuffixes.join(', ')})`,
          explanation: 'Appending words like "-login", "-secure", or "-verify" to a domain mimics an official portal.',
          evidence: `Host label ends with suffix "${domain.suspiciousDomainSuffixes[0]}".`,
        });
      }

      if (domain.sldWordCount >= 4 && structure.hyphenCountInSld >= 3) {
        const heavyMultiHyphen = domain.sldWordCount >= 5;
        push({
          ruleId: 'multi_hyphen_registered_domain',
          ruleName: 'Multiple Hyphenated Words in Registered Domain',
          category: 'hostStructure',
          severity: heavyMultiHyphen ? 'medium' : 'low',
          indicatorStrength: heavyMultiHyphen ? 'medium' : 'weak',
          weight: heavyMultiHyphen ? (w.multiHyphenSldHigh ?? 10) : (w.multiHyphenSld ?? 4),
          statusText: heavyMultiHyphen ? 'Flagged' : 'Noted',
          label: `Registered domain strings ${domain.sldWordCount} hyphenated words together`,
          explanation: 'Combining many hyphen-separated words inside a registered domain is weighed conservatively unless paired with stronger deception cues.',
          evidence: `Registered domain base "${domain.sld}" splits into ${domain.sldWordCount} hyphenated words.`,
        });
      }

      if (domain.hasNumericHeavyDomain) {
        push({
          ruleId: 'numeric_heavy_domain',
          ruleName: 'Excessive Digits in Registered Domain',
          category: 'hostStructure',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.numericHeavyDomain ?? 11,
          statusText: 'Flagged',
          label: 'High proportion of numbers inside registered domain',
          explanation: 'Domains dominated by digits often come from disposable or automated infrastructure.',
          evidence: `Registered domain "${domain.sld}" contains ${structure.digitsInSld} digits (${Math.round(structure.digitRatioInSld * 100)}%).`,
        });
      } else if (!structure.hasIpAddress && structure.digitsInSld >= 3) {
        push({
          ruleId: 'numeric_registered_domain',
          ruleName: 'Elevated Digits in Registered Domain',
          category: 'hostStructure',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.numericRegisteredDomain ?? 4,
          label: `Multiple numeric digits inside domain (${structure.digitsInSld})`,
          explanation: 'Several digits embedded in the registered domain name.',
          evidence: `Registered domain "${domain.sld}" includes ${structure.digitsInSld} digits.`,
        });
      }

      if (
        domain.hasNumericTld ||
        domain.hasEmptyLabelDots ||
        domain.hasLeadingOrTrailingHyphen
      ) {
        push({
          ruleId: 'unusual_hostname_formatting',
          ruleName: 'Unusual Hostname Formatting',
          category: 'hostStructure',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.unusualHostnameFormat ?? 12,
          statusText: 'Flagged',
          label: 'Malformed or irregular hostname label structure',
          explanation: 'Empty dot separators, trailing hyphens, or numeric extensions are abnormal for legitimate DNS hosts.',
          evidence: `Irregular formatting in host "${features.hostname}".`,
        });
      }

      if (domain.hasEmbeddedDomainInSubdomain && domain.embeddedDomainsInSubdomain && domain.embeddedDomainsInSubdomain.length > 0) {
        push({
          ruleId: 'embedded_domain_in_subdomain',
          ruleName: 'Domain-Formatted Label Embedded Inside Subdomain',
          category: 'hostStructure',
          severity: 'high',
          indicatorStrength: 'strong',
          weight: w.embeddedDomainInSubdomain ?? 32,
          statusText: 'Detected',
          label: `Deceptive domain-like string "${domain.embeddedDomainsInSubdomain[0]}" embedded inside subdomain`,
          explanation: 'Placing a "<name>.<tld>" pattern inside subdomains creates the false impression of visiting that embedded domain while connecting to a different registered host.',
          evidence: `Subdomain "${features.domainParts.subdomainStr}" embeds "${domain.embeddedDomainsInSubdomain.join(', ')}" before actual registered domain "${domain.registrableDomain}".`,
        });
      }

      if (domain.unrelatedEmbeddedDomains && domain.unrelatedEmbeddedDomains.length > 0) {
        push({
          ruleId: 'multiple_domain_strings',
          ruleName: 'Embedded External Domain Strings Inside URL',
          category: 'hostStructure',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.multipleDomainStrings ?? 11,
          statusText: 'Flagged',
          label: `URL embeds another domain name (${domain.unrelatedEmbeddedDomains[0]})`,
          explanation: 'Including an unrelated domain string inside paths or parameters can mislead users about the destination.',
          evidence: `Found embedded domain string(s): ${domain.unrelatedEmbeddedDomains.slice(0, 2).join(', ')}.`,
        });
      }

  }

  function evaluateCategoryD_BrandImpersonation(ctx) {
    const { features, domain, scriptInfo, w, push } = ctx;
    // =========================================================================
    // CATEGORY D: Visual Mimicry & Homograph Spoofing
    // (Pure rule-based analysis; zero brand or URL lists)
    // =========================================================================
    if (scriptInfo.hasMixedScriptsInLabel && domain.hasConfusableCharsInHost) {
      push({
        ruleId: 'idn_homoglyph_mimicry',
        ruleName: 'Mixed-Script IDN Homoglyph Visual Mimicry',
        category: 'brandImpersonation',
        severity: 'high',
        indicatorStrength: 'strong',
        weight: w.idnHomoglyphMimicry ?? 22,
        statusText: 'Detected',
        label: 'Visually confusable cross-script homoglyph characters mimic Latin text',
        explanation: 'Mixing non-Latin confusable homoglyphs (such as Cyrillic or Greek lookalikes) with Latin characters in a single label visually spoofs standard hostnames.',
        evidence: `Host "${domain.decodedHost || features.hostname}" combines scripts (${scriptInfo.scripts.join(' + ')}) with Unicode lookalikes.`,
      });
    }
  }

  function evaluateCategoryE_LureKeywords(ctx) {
    const { features, structure, domain, scriptInfo, patterns, kw, regInfo, th, w, push } = ctx;
    // =========================================================================
    // CATEGORY E: Suspicious Keywords & Semantic Combinations
    // =========================================================================
      const domainKw = (kw.byLocation && kw.byLocation.domain) || [];
      const allKw = kw.allUniqueKeywords || [];
      const catKw = kw.byCategory || {};
      const urgencyHits = catKw.urgency || [];
      const paymentHits = catKw.payment || [];
      const recoveryHits = catKw.recovery || [];
      const credHits = catKw.credential || [];

      // Determine whether the host possesses stronger suspicious or deceptive characteristics.
      // Individual keywords (e.g. "account", "settings", "login", "password") are weak indicators;
      // their risk significance elevates when combined with genuine structural deception or suspicious host traits.
      const isNewDomain = Boolean(regInfo && typeof regInfo.domainAgeDays === 'number' && regInfo.domainAgeDays <= (th.newlyRegisteredDays ?? 30));
      const hasDeceptiveSubdomainLures = structure.nonWwwSubdomainCount >= 2 && domainKw.length >= 2;

      const isSuspiciousHost =
        domain.isHighRiskTld ||
        domain.isModerateRiskTld ||
        structure.isPublicIp ||
        structure.hasObfuscatedIp ||
        domain.hasPunycode ||
        scriptInfo.hasMixedScriptsInLabel ||
        domain.hasConfusableCharsInHost ||
        domain.hasEmbeddedDomainInSubdomain ||
        domain.hasLookalikeDigitSubstitution ||
        (domain.suspiciousDomainPrefixes && domain.suspiciousDomainPrefixes.length > 0) ||
        (domain.suspiciousDomainSuffixes && domain.suspiciousDomainSuffixes.length > 0) ||
        structure.nonWwwSubdomainCount >= 3 ||
        hasDeceptiveSubdomainLures ||
        isNewDomain ||
        domain.hasRandomLookingDomain ||
        domain.hasHighDomainEntropy ||
        patterns.hasAtInAuthority ||
        patterns.hasHexEscapeInAuthority ||
        patterns.hasDoubleEncoding;

      if (allKw.length >= 3) {
        const inDomainCount = domainKw.length;
        // Clustering 3+ keywords on an unverified/suspicious host or with multiple domain keywords is elevated risk.
        // On a clean, ordinary domain (e.g. legitimate account portal with account, security, login),
        // treat as weak/noted rather than high-risk phishing proof.
        const isStrong = inDomainCount >= 2 || (isSuspiciousHost && inDomainCount >= 1);
        const isMedium = isSuspiciousHost || inDomainCount >= 1;
        push({
          ruleId: 'keywords_three_plus',
          ruleName: 'Multiple Suspicious Keywords Clustered',
          category: 'lureKeywords',
          severity: isStrong ? 'high' : (isMedium ? 'medium' : 'low'),
          indicatorStrength: isStrong ? 'strong' : (isMedium ? 'medium' : 'weak'),
          weight: isStrong ? (w.keywordsThreePlusDomain ?? 18) : (w.keywordsThreePlusPath ?? 11),
          statusText: isStrong || isMedium ? 'Flagged' : 'Noted',
          label: `Multiple security/account keywords (${allKw.slice(0, 4).join(', ')})`,
          explanation: isStrong || isMedium
            ? 'Clustering three or more authentication or urgency words on an unverified host is typical of credential-harvesting links.'
            : 'Multiple account/security terms present across URL path or query parameters.',
          evidence: `Matched ${allKw.length} keywords (${inDomainCount} in hostname): ${allKw.slice(0, 5).join(', ')}.`,
        });
      } else if (allKw.length === 2) {
        // Paired keywords: on legitimate sites, having an account subdomain (like myaccount or accounts)
        // alongside a path like /security or /settings or /login is standard workflow.
        // Increase significance to medium only when combined with stronger suspicious host characteristics
        // or when multiple keywords are embedded directly into the hostname.
        const multipleInHost = domainKw.length >= 2;
        const elevated = isSuspiciousHost || multipleInHost;
        push({
          ruleId: 'keywords_two',
          ruleName: 'Two Suspicious Keywords Present',
          category: 'lureKeywords',
          severity: elevated ? 'medium' : 'low',
          indicatorStrength: elevated ? 'medium' : 'weak',
          weight: elevated ? (w.keywordsTwoDomain ?? 11) : (w.keywordsTwoPath ?? 4),
          statusText: elevated ? 'Flagged' : 'Noted',
          label: `Paired security/login keywords (${allKw.join(', ')})`,
          explanation: elevated
            ? 'Two sensitive workflow terms appear on a host with elevated risk characteristics.'
            : 'Two sensitive workflow terms appear together in this URL.',
          evidence: `Matched keywords: ${allKw.join(', ')}.`,
        });
      } else if (allKw.length === 1) {
        const inHost = domainKw.length === 1;
        // On a clean, ordinary domain without suspicious characteristics, a single keyword
        // (e.g. "account" in myaccount.google.com or "login" in example.com/login) is normal web workflow.
        const elevated = inHost && isSuspiciousHost;
        push({
          ruleId: 'keywords_one',
          ruleName: 'Single Authentication Keyword',
          category: 'lureKeywords',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: elevated ? (w.keywordsOneDomain ?? 5) : (inHost ? 2 : (w.keywordsOnePath ?? 2)),
          statusText: elevated ? 'Flagged' : 'Noted',
          label: inHost
            ? `Authentication/trust term in domain (${allKw[0]})`
            : `Single workflow keyword (${allKw[0]})`,
          explanation: 'A single common keyword is not evidence of phishing on its own, though location matters.',
          evidence: `Keyword "${allKw[0]}" found in ${inHost ? 'hostname' : 'path/query'}.`,
        });
      }

      if (urgencyHits.length >= 2) {
        push({
          ruleId: 'multiple_urgency_keywords',
          ruleName: 'Multiple Urgency or Restriction Keywords',
          category: 'lureKeywords',
          severity: 'medium',
          indicatorStrength: 'strong',
          weight: w.multipleUrgencyKeywords ?? 14,
          statusText: 'Flagged',
          label: `Urgency/account-restriction language (${urgencyHits.slice(0, 3).join(', ')})`,
          explanation: 'Phishing lures often warn that an account is locked, suspended, or restricted to rush victims.',
          evidence: `Detected urgency terms: ${urgencyHits.join(', ')}.`,
        });
      }

      const passwordSpecific = credHits.filter((word) =>
        ['password', 'passcode', 'credential', 'credentials', 'otp', 'pin'].includes(word)
      ).concat(recoveryHits.filter((word) => ['reset', 'recover', 'recovery'].includes(word)));

      if (passwordSpecific.length > 0 && !structure.isPrivateOrLocalIp) {
        const inDomain = domainKw.some((d) => passwordSpecific.includes(d));
        // A password/reset keyword in the path on a clean, legitimate domain is standard settings/recovery functionality.
        // It should only be flagged as suspicious when in the domain itself or when paired with suspicious host characteristics.
        const isDeceptive = inDomain || isSuspiciousHost;
        if (isDeceptive) {
          push({
            ruleId: 'password_keyword_unrelated_domain',
            ruleName: 'Password/Reset Terms on Suspicious Domain',
            category: 'lureKeywords',
            severity: inDomain ? 'high' : 'medium',
            indicatorStrength: inDomain ? 'medium' : 'weak',
            weight: inDomain ? (w.passwordKeywordDomain ?? 14) : (w.passwordKeywordPath ?? 7),
            statusText: inDomain ? 'Flagged' : 'Noted',
            label: `Password/recovery term (${passwordSpecific[0]}) on unverified host`,
            explanation: 'Password, PIN, OTP, or recovery terms warrant verifying you trust the domain owner before typing credentials.',
            evidence: `Found "${passwordSpecific.join(', ')}" on flagged host "${domain.registrableDomain}".`,
          });
        }
      }

      if (paymentHits.length > 0 && isSuspiciousHost) {
        push({
          ruleId: 'payment_keyword_suspicious_domain',
          ruleName: 'Payment Keywords Combined With Suspicious Domain',
          category: 'lureKeywords',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.paymentKeywordSuspiciousDomain ?? 12,
          statusText: 'Flagged',
          label: `Financial/payment terms (${paymentHits.slice(0, 2).join(', ')}) on suspicious host`,
          explanation: 'Billing, banking, or wallet keywords paired with risky host characteristics suggest credential or payment theft.',
          evidence: `Payment keywords "${paymentHits.join(', ')}" on "${features.hostname}".`,
        });
      }

  }

  function evaluateCategoryF_PathAndQuery(ctx) {
    const { features, structure, domain, scriptInfo, pq, kw, w, push } = ctx;
    // =========================================================================
    // CATEGORY F: Suspicious URL Paths & Query Parameters
    // =========================================================================
      const domainKw = (kw.byLocation && kw.byLocation.domain) || [];
      const hostRiskyForPath =
        domain.isHighRiskTld ||
        domain.isModerateRiskTld ||
        structure.isPublicIp ||
        domain.hasPunycode ||
        scriptInfo.hasMixedScriptsInLabel ||
        domain.hasConfusableCharsInHost ||
        domain.hasEmbeddedDomainInSubdomain ||
        domain.hasLookalikeDigitSubstitution ||
        (domain.suspiciousDomainPrefixes && domain.suspiciousDomainPrefixes.length > 0) ||
        (domain.suspiciousDomainSuffixes && domain.suspiciousDomainSuffixes.length > 0) ||
        (domainKw.length >= 2 && structure.nonWwwSubdomainCount >= 2);

      if (
        (kw.pathCredentialHits && kw.pathCredentialHits.length > 0) &&
        hostRiskyForPath
      ) {
        push({
          ruleId: 'login_path_on_suspicious_domain',
          ruleName: 'Login/Auth Path on Suspicious Domain',
          category: 'pathAndQuery',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.loginPathSuspiciousDomain ?? 12,
          statusText: 'Flagged',
          label: 'Authentication path hosted on a suspicious domain',
          explanation: 'A login or verification path paired with untrusted domain characteristics increases risk.',
          evidence: `Path keywords "${kw.pathCredentialHits.slice(0, 3).join(', ')}" on "${features.hostname}".`,
        });
      }

      if (pq.hasSuspiciousLoginFilename) {
        push({
          ruleId: 'suspicious_login_filename',
          ruleName: 'Suspicious Login Script/Page Filename',
          category: 'pathAndQuery',
          severity: hostRiskyForPath || features.isHttp ? 'medium' : 'low',
          indicatorStrength: hostRiskyForPath || features.isHttp ? 'medium' : 'weak',
          weight: hostRiskyForPath || features.isHttp ? (w.suspiciousLoginFilenameHigh ?? 11) : (w.suspiciousLoginFilename ?? 5),
          statusText: hostRiskyForPath || features.isHttp ? 'Flagged' : 'Noted',
          label: `Login script/page filename ("${pq.leafSegment}")`,
          explanation: 'Static script filenames like login.php or webscr.php are frequently used by cloned phishing kits.',
          evidence: `Target file in path is "${pq.leafSegment}".`,
        });
      }

      if (pq.hasFakeVerificationFilename) {
        push({
          ruleId: 'fake_verification_filename',
          ruleName: 'Verification/Unlock Script Page Name',
          category: 'pathAndQuery',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.fakeVerificationFilename ?? 10,
          statusText: 'Flagged',
          label: `Verification-themed page filename ("${pq.leafSegment}")`,
          explanation: 'Page filenames referencing verification or account unlocking are commonly used in phishing kits.',
          evidence: `Filename "${pq.leafSegment}" detected in path.`,
        });
      }

      if (pq.hasPasswordResetPath && (domain.hasEmbeddedDomainInSubdomain || hostRiskyForPath)) {
        push({
          ruleId: 'suspicious_password_reset_path',
          ruleName: 'Password Reset Path on Suspicious Domain',
          category: 'pathAndQuery',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.passwordResetPath ?? 9,
          statusText: 'Flagged',
          label: 'Password reset path paired with suspicious domain indicators',
          explanation: 'Account recovery workflows paired with risky or deceptive domain patterns warrant verification.',
          evidence: `Password recovery path detected on "${features.hostname}".`,
        });
      }

      if (pq.hasPaymentPath && (domain.hasEmbeddedDomainInSubdomain || domain.hasLookalikeDigitSubstitution || domain.isHighRiskTld || structure.isPublicIp)) {
        push({
          ruleId: 'payment_checkout_unrelated_domain',
          ruleName: 'Payment/Checkout Path on Suspicious Host',
          category: 'pathAndQuery',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.paymentCheckoutPath ?? 11,
          statusText: 'Flagged',
          label: 'Payment or checkout path paired with risky host cues',
          explanation: 'Checkout, billing, or card update paths on high-risk or deceptive host structures increase payment fraud exposure.',
          evidence: `Payment path found on flagged host "${domain.registrableDomain}".`,
        });
      }

      if (pq.hasLongRandomPathSegment) {
        push({
          ruleId: 'long_random_path_segment',
          ruleName: 'Long Random-Looking Path Segment',
          category: 'pathAndQuery',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.longRandomPathSegment ?? 4,
          label: 'Random-looking folder or token in URL path',
          explanation: 'Long randomized path tokens are sometimes generated per target to evade static blocklists.',
          evidence: `Path contains high-entropy segment up to ${pq.maxPathSegmentLength} characters.`,
        });
      }

      if (pq.randomLookingQueryCount >= 1) {
        push({
          ruleId: 'random_looking_query_values',
          ruleName: 'Random-Looking Query Parameter Values',
          category: 'pathAndQuery',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: pq.randomLookingQueryCount >= 2 ? (w.randomQueryValuesMulti ?? 6) : (w.randomQueryValues ?? 3),
          label: 'Random or opaque tokens inside query parameters',
          explanation: 'Randomized query parameter values may represent session tracking or victim identifiers.',
          evidence: `Detected ${pq.randomLookingQueryCount} high-entropy query parameter value(s).`,
        });
      }

      if (pq.encodedQueryParamCount >= 3) {
        push({
          ruleId: 'excessive_encoded_query_params',
          ruleName: 'Multiple Encoded Query Parameters',
          category: 'pathAndQuery',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.encodedQueryParams ?? 7,
          statusText: 'Flagged',
          label: `Multiple encoded query parameters (${pq.encodedQueryParamCount})`,
          explanation: 'Several URL-encoded or Base64-padded query fields conceal payload values.',
          evidence: `${pq.encodedQueryParamCount} parameters carry encoded data.`,
        });
      }

      if (pq.hasDoubleExtension || (pq.hasMisleadingDocumentName && pq.hasExecutableExtension)) {
        push({
          ruleId: 'misleading_double_extension',
          ruleName: 'Misleading Document / Executable Double Extension',
          category: 'pathAndQuery',
          severity: 'high',
          indicatorStrength: 'strong',
          weight: w.doubleExtensionFile ?? 34,
          statusText: 'Detected',
          label: `Deceptive double file extension ("${pq.leafSegment}")`,
          explanation: 'Filenames posing as PDF or Office documents while serving executables, scripts, or HTML lures are a classic phishing/malware trick.',
          evidence: `Leaf path ends with "${pq.leafSegment}".`,
        });
      } else if (pq.hasExecutableExtension) {
        push({
          ruleId: 'executable_extension',
          ruleName: 'Direct Executable or Script Installer Extension',
          category: 'pathAndQuery',
          severity: 'high',
          indicatorStrength: 'strong',
          weight: w.executableExtension ?? 22,
          statusText: 'Flagged',
          label: `Direct link to executable/script file (.${pq.leafExtension})`,
          explanation: 'Links ending directly in executable or installer extensions pose malware delivery risk.',
          evidence: `URL path targets ".${pq.leafExtension}" file ("${pq.leafSegment}").`,
        });
      } else if (pq.hasArchiveExtension) {
        push({
          ruleId: 'archive_extension',
          ruleName: 'Compressed Archive File Extension',
          category: 'pathAndQuery',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.archiveExtension ?? 7,
          label: `Direct link to compressed archive (.${pq.leafExtension})`,
          explanation: 'Archive downloads can bundle uninspected scripts or credential-theft attachments.',
          evidence: `URL targets ".${pq.leafExtension}" archive ("${pq.leafSegment}").`,
        });
      } else if (pq.hasMisleadingDocumentName) {
        push({
          ruleId: 'misleading_document_filename',
          ruleName: 'Document-Themed Web Page Lure',
          category: 'pathAndQuery',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.misleadingDocName ?? 14,
          statusText: 'Flagged',
          label: `Document/invoice-themed filename ("${pq.leafSegment}")`,
          explanation: 'Web pages named like invoices, receipts, or shipping documents are frequently used in attachment-style phishing.',
          evidence: `Path ends with "${pq.leafSegment}".`,
        });
      } else if (pq.hasScriptExtension && (kw.allUniqueKeywords.length > 0 || hostRiskyForPath)) {
        push({
          ruleId: 'suspicious_script_page_extension',
          ruleName: 'Server Script File With Sensitive Context',
          category: 'pathAndQuery',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.scriptExtension ?? 5,
          label: `Server script endpoint (.${pq.leafExtension}) in sensitive context`,
          explanation: 'Script filename paired with login, verification, or risky domain features.',
          evidence: `Endpoint file is "${pq.leafSegment}".`,
        });
      }

      if (pq.hasExtensionWithSuspiciousQuery) {
        push({
          ruleId: 'extension_with_suspicious_query',
          ruleName: 'File Endpoint With Victim-Prefill or Command Query',
          category: 'pathAndQuery',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.extensionWithSuspiciousQuery ?? 10,
          statusText: 'Flagged',
          label: 'Page filename combined with victim email prefill or session command query',
          explanation: 'Phishing kits often pass pre-filled target email addresses or kit commands into static HTML/PHP files.',
          evidence: `File ".${pq.leafExtension}" combined with ${pq.emailPrefillCount > 0 ? 'email parameter' : 'command/session parameters'}.`,
        });
      }

      if (pq.externalUrlParams && pq.externalUrlParams.length > 0 && pq.externalRedirectParams.length === 0) {
        push({
          ruleId: 'query_contains_complete_url',
          ruleName: 'Query Parameter Contains Complete URL',
          category: 'pathAndQuery',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.queryContainsCompleteUrl ?? 5,
          label: 'Query parameter embeds another complete URL',
          explanation: 'Embedding a complete web address inside parameters can reflect tracking or redirection flows.',
          evidence: `Parameter "${pq.externalUrlParams[0].key}" holds a full URL.`,
        });
      }

  }

  function evaluateCategoryG_RedirectPatterns(ctx) {
    const { pq, w, push } = ctx;
    // =========================================================================
    // CATEGORY G: Redirect & Parameter Patterns (Never follow/fetch URL!)
    // =========================================================================

    if (pq.nestedRedirectCount > 0) {
      push({
        ruleId: 'nested_redirect_urls',
        ruleName: 'Nested Redirect URL Chain Suspected',
        category: 'redirectPatterns',
        severity: 'high',
        indicatorStrength: 'strong',
        weight: w.nestedRedirectUrls ?? 18,
        statusText: 'Flagged',
        label: 'Nested redirect URL chain suspected in parameters',
        explanation: 'Multiple chained redirect destinations are strongly associated with evading link inspection.',
        evidence: `Redirect target embeds another redirect parameter or chained URL (${pq.nestedRedirectCount} nesting pattern(s)).`,
      });
    }

    if (pq.redirectParams && pq.redirectParams.length >= 2) {
      push({
        ruleId: 'multiple_redirect_params',
        ruleName: 'Multiple Redirect Parameters',
        category: 'redirectPatterns',
        severity: 'medium',
        indicatorStrength: 'medium',
        weight: w.multipleRedirectParams ?? 14,
        statusText: 'Flagged',
        label: `Multiple redirect-like parameters detected (${pq.redirectParams.map((r) => r.key).slice(0, 3).join(', ')})`,
        explanation: 'Carrying multiple redirect or callback targets suggests suspected redirection chaining.',
        evidence: `Found ${pq.redirectParams.length} redirect parameters (${pq.redirectParams.map((r) => r.key).join(', ')}).`,
      });
    }

    if (pq.encodedExternalRedirectCount > 0) {
      const extKey =
        (pq.externalRedirectParams[0] && pq.externalRedirectParams[0].key) ||
        (pq.externalUrlParams && pq.externalUrlParams[0] && pq.externalUrlParams[0].key) ||
        'url';
      push({
        ruleId: 'encoded_external_redirect',
        ruleName: 'Encoded External Redirect Destination',
        category: 'redirectPatterns',
        severity: 'medium',
        indicatorStrength: 'medium',
        weight: w.encodedExternalRedirect ?? 12,
        statusText: 'Flagged',
        label: 'Encoded external destination inside redirect parameter',
        explanation: 'Redirect destination uses URL encoding or Base64 wrapping, making target domains harder to spot.',
        evidence: `Redirect carrier "${extKey}" contains an encoded external link.`,
      });
    }

    if (pq.isOpenRedirectStructure) {
      push({
        ruleId: 'open_redirect_structure',
        ruleName: 'Open-Redirect URL Structure Suspected',
        category: 'redirectPatterns',
        severity: 'medium',
        indicatorStrength: 'medium',
        weight: w.openRedirectStructure ?? 12,
        statusText: 'Flagged',
        label: 'Open-redirect path combined with external destination',
        explanation: 'Redirection endpoint paired with an unrelated target domain may forward visitors off-site.',
        evidence: `Redirect parameter forwards toward unrelated host "${pq.externalRedirectParams[0].targetHost}".`,
      });
    } else if (pq.externalRedirectParams && pq.externalRedirectParams.length > 0) {
      push({
        ruleId: 'redirect_to_unrelated_domain',
        ruleName: 'Redirect Parameter Pointing to Unrelated Domain',
        category: 'redirectPatterns',
        severity: 'medium',
        indicatorStrength: 'medium',
        weight: w.redirectToUnrelatedDomain ?? 10,
        statusText: 'Flagged',
        label: `Suspected external redirect toward "${pq.externalRedirectParams[0].targetHost}"`,
        explanation: 'A redirect-style query parameter points away from the current host to an unrelated domain.',
        evidence: `Parameter "${pq.externalRedirectParams[0].key}" specifies target "${pq.externalRedirectParams[0].targetHost}".`,
      });
    }

  }

  function evaluateCategoryH_TransportAndProtocol(ctx) {
    const { features, structure, domain, patterns, kw, scriptInfo, w, push } = ctx;
    // =========================================================================
    // CATEGORY H: Protocol & Port Checks
    // =========================================================================
    const hasCredentialContext =
      (kw.domainCredentialHits && kw.domainCredentialHits.length > 0) ||
      (kw.pathCredentialHits && kw.pathCredentialHits.length > 0) ||
      domain.hasEmbeddedDomainInSubdomain;

    if (features.isHttp && !structure.isPrivateOrLocalIp) {
      if (hasCredentialContext) {
        push({
          ruleId: 'http_with_credentials',
          ruleName: 'Unencrypted HTTP With Credential Context',
          category: 'transportAndProtocol',
          severity: 'high',
          indicatorStrength: 'strong',
          weight: w.httpWithCredentialContext ?? 16,
          statusText: 'Flagged',
          label: 'Unencrypted HTTP on credential-related URL',
          explanation: 'Using plain HTTP alongside authentication or brand wording exposes submitted data and lacks TLS authentication.',
          evidence: 'Scheme is insecure "http://" while authentication or brand signals are present.',
        });
      } else {
        push({
          ruleId: 'http_plain',
          ruleName: 'Unencrypted HTTP Connection',
          category: 'transportAndProtocol',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.httpPlainBaseline ?? 4,
          label: 'Unencrypted HTTP connection',
          explanation: 'Site lacks HTTPS encryption, though plain HTTP alone does not confirm phishing.',
          evidence: 'URL uses unencrypted "http://" scheme.',
        });
      }
    }

    if (
      features.isHttps &&
      (domain.hasEmbeddedDomainInSubdomain ||
        domain.hasLookalikeDigitSubstitution ||
        patterns.hasAtInAuthority ||
        scriptInfo.hasMixedScriptsInLabel)
    ) {
      push({
        ruleId: 'https_on_suspicious_impersonation',
        ruleName: 'HTTPS on Suspicious or Deceptive Domain',
        category: 'transportAndProtocol',
        severity: 'medium',
        indicatorStrength: 'medium',
        weight: w.httpsFalseSecurityNote ?? 0,
        statusText: 'Noted',
        label: 'HTTPS certificate does not validate misleading domain structure',
        explanation: 'Phishing sites routinely obtain free HTTPS certificates; encryption alone never guarantees legitimacy.',
        evidence: `URL uses HTTPS on flagged hostname "${features.hostname}".`,
      });
    }

    if (features.hasNonStandardPort && !structure.isPrivateOrLocalIp) {
      push({
        ruleId: 'non_standard_port',
        ruleName: 'Non-Standard Network Port',
        category: 'transportAndProtocol',
        severity: 'medium',
        indicatorStrength: 'medium',
        weight: w.nonStandardPort ?? 11,
        statusText: 'Flagged',
        label: `Unusual network port (:${features.port})`,
        explanation: 'Standard websites run on ports 80 or 443; alternate ports can indicate ephemeral phishing infrastructure.',
        evidence: `URL specifies port ":${features.port}".`,
      });
    }

    if (patterns.unusualProtocolFormatting) {
      push({
        ruleId: 'unusual_protocol_format',
        ruleName: 'Unusual Protocol Formatting',
        category: 'transportAndProtocol',
        severity: 'low',
        indicatorStrength: 'weak',
        weight: w.unusualProtocolFormat ?? 6,
        label: 'Non-standard URL scheme formatting',
        explanation: 'Protocol-relative prefixes, extra scheme slashes, or irregular scheme casing were observed in raw input.',
        evidence: 'Raw scheme formatting deviated from standard "https://host" syntax.',
      });
    }

    if (patterns.hasHttpsKeywordInDomain) {
      push({
        ruleId: 'https_in_domain',
        ruleName: 'Misleading Protocol Word in Hostname',
        category: 'transportAndProtocol',
        severity: 'medium',
        indicatorStrength: 'medium',
        weight: w.httpsInDomainName ?? 11,
        statusText: 'Flagged',
        label: 'Misleading "https", "http", or "ssl" text inside domain name',
        explanation: 'Embedding protocol words inside a domain name attempts to trick users into assuming security.',
        evidence: `Hostname "${features.hostname}" embeds protocol/TLS terms.`,
      });
    }

    if (patterns.hasProtocolInPath) {
      push({
        ruleId: 'protocol_in_path',
        ruleName: 'Embedded Protocol String Inside URL Path',
        category: 'transportAndProtocol',
        severity: 'medium',
        indicatorStrength: 'medium',
        weight: w.protocolInPath ?? 10,
        statusText: 'Flagged',
        label: 'Embedded "http://" or "https://" inside URL path',
        explanation: 'Protocol prefixes inside folder paths can signal nested redirects or deceptive masking.',
        evidence: 'Detected protocol delimiter embedded within URL path.',
      });
    }

    if (patterns.hasMultipleProtocolStrings) {
      push({
        ruleId: 'multiple_protocol_strings',
        ruleName: 'Multiple Protocol Strings in URL',
        category: 'transportAndProtocol',
        severity: 'medium',
        indicatorStrength: 'medium',
        weight: w.multipleProtocolStrings ?? 10,
        statusText: 'Flagged',
        label: 'Multiple HTTP/HTTPS protocol strings inside one URL',
        explanation: 'Presence of multiple protocol headers suggests chained external forwarding.',
        evidence: 'URL contains more than one "http://" or "https://" sequence.',
      });
    }

  }

  function evaluateCategoryI_DomainReputation(ctx) {
    const { domain, regInfo, th, w, push } = ctx;
    // =========================================================================
    // CATEGORY I: TLD & Domain Reputation (TLD Extensions + Optional Registration Data)
    // =========================================================================
    if (domain.isHighRiskTld) {
      push({
        ruleId: 'high_risk_tld',
        ruleName: 'High-Abuse Top-Level Domain',
        category: 'domainReputation',
        severity: 'medium',
        indicatorStrength: 'medium',
        weight: w.highRiskTld ?? 18,
        statusText: 'Flagged',
        label: `High-abuse top-level domain (.${domain.tld})`,
        explanation: 'This domain extension experiences elevated abuse in disposable phishing campaigns, though an unusual TLD alone does not prove phishing.',
        evidence: `Domain ends with ".${domain.tld}".`,
      });
    } else if (domain.isModerateRiskTld) {
      push({
        ruleId: 'moderate_risk_tld',
        ruleName: 'Less-Common or Moderately Abused TLD',
        category: 'domainReputation',
        severity: 'low',
        indicatorStrength: 'weak',
        weight: w.moderateRiskTld ?? 7,
        label: `Uncommon TLD (.${domain.tld})`,
        explanation: 'Less common extension noted as a minor signal; legitimate sites also use non-traditional TLDs.',
        evidence: `Domain ends with ".${domain.tld}".`,
      });
    }

    // Optional external registration / domain-age data (only evaluated when supplied by a configured provider!)
    if (regInfo && typeof regInfo === 'object') {
      if (typeof regInfo.domainAgeDays === 'number' && regInfo.domainAgeDays >= 0) {
        if (regInfo.domainAgeDays <= th.veryRecentDays) {
          push({
            ruleId: 'very_recent_domain',
            ruleName: 'Very Recently Created Domain',
            category: 'domainReputation',
            severity: 'high',
            indicatorStrength: 'strong',
            weight: w.veryRecentDomain ?? 24,
            statusText: 'Flagged',
            label: `Domain registered within the last ${regInfo.domainAgeDays} days`,
            explanation: 'Phishing campaigns often spin up fresh domains shortly before launching attacks.',
            evidence: `Provided registration data shows domain age of ${regInfo.domainAgeDays} day(s).`,
          });
        } else if (regInfo.domainAgeDays <= th.newlyRegisteredDays) {
          push({
            ruleId: 'newly_registered_domain',
            ruleName: 'Newly Registered Domain',
            category: 'domainReputation',
            severity: 'medium',
            indicatorStrength: 'medium',
            weight: w.newlyRegisteredDomain ?? 14,
            statusText: 'Caution',
            label: `Newly registered domain (${regInfo.domainAgeDays} days old)`,
            explanation: 'Relatively new domain registration warrants extra caution when entering credentials.',
            evidence: `Provided registration data shows domain age of ${regInfo.domainAgeDays} days.`,
          });
        }
      } else if (regInfo.status === 'unavailable') {
        push({
          ruleId: 'registration_data_unavailable',
          ruleName: 'Domain Registration Data Unavailable',
          category: 'domainReputation',
          severity: 'low',
          indicatorStrength: 'weak',
          weight: w.registrationUnavailable ?? 2,
          label: 'Domain registration records unavailable',
          explanation: 'Registration lookup returned no public age record; missing WHOIS/RDAP data does not prove phishing.',
          evidence: 'Configured registration provider reported status "unavailable".',
        });
      }
    }

  }

  function evaluatePageContextRules(ctx) {
    const { features, structure, domain, kw, pageSignals, w, push } = ctx;
    // =========================================================================
    // PAGE CONTEXT (Optional lightweight signals from content.js)
    // =========================================================================
    if (pageSignals && typeof pageSignals === 'object') {
      if (pageSignals.hasPasswordField && features.isHttp && !structure.isPrivateOrLocalIp) {
        push({
          ruleId: 'password_over_http',
          ruleName: 'Password Input Over Unencrypted HTTP',
          category: 'pageContext',
          severity: 'high',
          indicatorStrength: 'strong',
          weight: w.passwordFieldOnHttp ?? 12,
          statusText: 'Flagged',
          label: 'Password input detected over unencrypted HTTP',
          explanation: 'The webpage requests a password without TLS encryption.',
          evidence: 'Active DOM contains a password input field on an HTTP origin.',
        });
      }
      if (
        pageSignals.hasCrossOriginForm &&
        (domain.hasMisleadingDomain || domain.isHighRiskTld || (kw.domainCredentialHits && kw.domainCredentialHits.length > 0))
      ) {
        push({
          ruleId: 'cross_origin_form',
          ruleName: 'Cross-Origin Form Submission on Suspicious Host',
          category: 'pageContext',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: w.crossOriginFormOnSuspiciousHost ?? 10,
          statusText: 'Flagged',
          label: 'Form submits user input to an external domain',
          explanation: 'Posting credentials from a suspicious page to a different domain suggests data exfiltration.',
          evidence: 'Form action target points outside the current website origin.',
        });
      }
    }

  }

  // Declarative Category J combination rules executed uniformly by the central rule pipeline
  const COMBO_RULE_DEFINITIONS = [
    {
      ruleId: 'combo_ip_plus_credential',
      evaluate: (c) =>
        (c.structure.isPublicIp || c.structure.hasObfuscatedIp) &&
        (c.domainOrPathLogin ||
          c.domainOrPathVerify ||
          c.domainOrPathRecovery ||
          Boolean(c.kw.byCategory && (c.kw.byCategory.credential.length > 0 || c.kw.byCategory.payment.length > 0))) && {
          ruleId: 'combo_ip_plus_credential',
          ruleName: 'Raw IP Host + Credential/Login Keywords',
          category: 'indicatorCombinations',
          severity: 'high',
          indicatorStrength: 'strong',
          weight: c.w.comboIpPlusCredential ?? 22,
          statusText: 'Detected',
          label: 'Login or credential workflow served directly from an IP address',
          explanation: 'Legitimate authentication services virtually never run directly from raw IP URLs.',
          evidence: `IP host "${c.features.hostname}" paired with sensitive workflow terms.`,
        },
    },
    {
      ruleId: 'combo_punycode_plus_lure',
      evaluate: (c) =>
        (c.domain.hasPunycode || c.scriptInfo.hasMixedScriptsInLabel || c.domain.rawHostHasNonAscii) &&
        (c.scriptInfo.hasMixedScriptsInLabel ||
          c.domain.hasConfusableCharsInHost ||
          c.domainOrPathLogin ||
          c.domainOrPathVerify ||
          c.domainOrPathRecovery ||
          c.domain.hasSuspiciousTld) && {
          ruleId: 'combo_punycode_plus_lure',
          ruleName: 'Punycode/IDN + Homoglyph or Credential Cue',
          category: 'indicatorCombinations',
          severity: 'high',
          indicatorStrength: 'strong',
          weight: c.w.comboPunycodePlusLure ?? 22,
          statusText: 'Detected',
          label: 'Punycode / Unicode obfuscation paired with script spoofing or credential cues',
          explanation: 'IDN encoding or mixed scripts paired with confusable glyphs or authentication terms indicates a homograph attack.',
          evidence: `Decoded host "${c.domain.decodedHost || c.features.hostname}" triggers multi-signal IDN risk.`,
        },
    },
    {
      ruleId: 'combo_random_domain_plus_keywords',
      evaluate: (c) =>
        c.domain.hasRandomLookingDomain &&
        c.kw.allUniqueKeywords &&
        c.kw.allUniqueKeywords.length >= 2 && {
          ruleId: 'combo_random_domain_plus_keywords',
          ruleName: 'Random-Looking Domain + Multiple Phishing Keywords',
          category: 'indicatorCombinations',
          severity: 'high',
          indicatorStrength: 'strong',
          weight: c.w.comboRandomDomainPlusKeywords ?? 20,
          statusText: 'Detected',
          label: 'High-randomness domain paired with multiple authentication keywords',
          explanation: 'Generated-looking domains hosting multi-keyword login or reset paths strongly signal active phishing kits.',
          evidence: `Random SLD "${c.domain.sld}" combined with keywords: ${c.kw.allUniqueKeywords.slice(0, 3).join(', ')}.`,
        },
    },
    {
      ruleId: 'combo_encoded_redirect_plus_lure',
      evaluate: (c) =>
        c.pq.encodedExternalRedirectCount > 0 &&
        (c.domainOrPathLogin ||
          c.domainOrPathVerify ||
          c.domainOrPathRecovery ||
          (c.domain.unrelatedEmbeddedDomains && c.domain.unrelatedEmbeddedDomains.length > 0) ||
          c.pq.emailPrefillCount > 0 ||
          c.pq.hasSuspiciousExternalRedirectTarget) && {
          ruleId: 'combo_encoded_redirect_plus_lure',
          ruleName: 'Encoded Redirect + Credential/Destination Lure',
          category: 'indicatorCombinations',
          severity: 'high',
          indicatorStrength: 'strong',
          weight: c.w.comboEncodedRedirectPlusLure ?? 22,
          statusText: 'Detected',
          label: 'Encoded external redirect combined with sensitive workflow or embedded domain cues',
          explanation: 'Obscuring an external redirect destination inside authentication or domain-referencing links signals open-redirect abuse.',
          evidence: 'Encoded external redirect target co-occurs with credential or embedded domain cues.',
        },
    },
    {
      ruleId: 'combo_keywords_plus_new_domain',
      evaluate: (c) =>
        c.regInfo &&
        typeof c.regInfo.domainAgeDays === 'number' &&
        c.regInfo.domainAgeDays <= c.th.newlyRegisteredDays &&
        c.kw.allUniqueKeywords.length >= 2 && {
          ruleId: 'combo_keywords_plus_new_domain',
          ruleName: 'Multiple Suspicious Keywords + Newly Registered Domain',
          category: 'indicatorCombinations',
          severity: 'high',
          indicatorStrength: 'strong',
          weight: c.w.comboKeywordsPlusNewDomain ?? 20,
          statusText: 'Detected',
          label: 'Multiple security keywords on a newly registered domain',
          explanation: 'Newly created domains hosting multiple login or verification terms are high-risk phishing indicators.',
          evidence: `Domain age (${c.regInfo.domainAgeDays}d) paired with ${c.kw.allUniqueKeywords.length} lure keywords.`,
        },
    },
    {
      ruleId: 'combo_params_plus_encoded_external_url',
      evaluate: (c) =>
        c.structure.queryParamCount >= 5 &&
        c.pq.encodedExternalRedirectCount > 0 && {
          ruleId: 'combo_params_plus_encoded_external_url',
          ruleName: 'Excessive Query Parameters + Encoded External URL',
          category: 'indicatorCombinations',
          severity: 'medium',
          indicatorStrength: 'medium',
          weight: c.w.comboParamsPlusEncodedExternal ?? 14,
          statusText: 'Flagged',
          label: 'Dense query parameters concealing an encoded external redirect',
          explanation: 'High parameter counts can bury an encoded third-party forwarding destination.',
          evidence: `${c.structure.queryParamCount} query parameters accompany an encoded external URL target.`,
        },
    },
    {
      ruleId: 'combo_authority_deception',
      evaluate: (c) => {
        const hasAuthTrick =
          c.patterns.hasAtInAuthority ||
          c.patterns.hasBackslashInAuthority ||
          c.patterns.hasEncodedAt ||
          c.patterns.hasMultipleAt ||
          c.patterns.hasHexEscapeInAuthority;
        if (!hasAuthTrick) return null;
        const secondaryCue =
          c.patterns.hasDomainShapedUserinfo ||
          c.domain.hasEmbeddedDomainInSubdomain ||
          c.domainOrPathLogin ||
          c.domainOrPathVerify ||
          c.domain.isHighRiskTld ||
          (c.pq.externalRedirectParams && c.pq.externalRedirectParams.length > 0) ||
          (c.patterns.hasAtInAuthority && c.patterns.hasBackslashInAuthority) ||
          c.patterns.hasEncodedAt;
        if (!secondaryCue) return null;
        return {
          ruleId: 'combo_authority_deception',
          ruleName: 'Authority Deception Paired With Lure or Redirect Signal',
          category: 'indicatorCombinations',
          severity: 'high',
          indicatorStrength: 'strong',
          weight: c.w.comboAuthorityDeception ?? 26,
          statusText: 'Detected',
          label: 'URL authority deception combined with decoy host, credential, or multi-trick cues',
          explanation: 'Manipulating URL authority delimiters (such as @, %40, or \\) alongside decoy hosts or login cues masks the actual destination server.',
          evidence: `Authority section obfuscation detected before connecting to "${c.features.hostname}".`,
        };
      },
    },
    {
      ruleId: 'combo_risky_tld_plus_lure',
      evaluate: (c) => {
        const domainKwCount = (c.domainKw && c.domainKw.length) || 0;
        const allKwCount = (c.kw.allUniqueKeywords && c.kw.allUniqueKeywords.length) || 0;
        const hasWorkflowSignal =
          c.pq.hasSuspiciousLoginFilename ||
          c.pq.hasFakeVerificationFilename ||
          c.pq.hasPaymentPath ||
          c.pq.emailPrefillCount > 0;
        const hasStructuralHostTrick =
          c.domain.hasLookalikeDigitSubstitution || c.domain.hasEmbeddedDomainInSubdomain;
        const hitHighRisk =
          c.domain.isHighRiskTld &&
          (c.domainOrPathLogin ||
            c.domainOrPathVerify ||
            c.domainOrPathRecovery ||
            hasWorkflowSignal ||
            hasStructuralHostTrick ||
            c.hasSuspensionLanguage ||
            allKwCount >= 2);
        const hitModerateRisk =
          c.domain.isModerateRiskTld &&
          (domainKwCount >= 1 || hasStructuralHostTrick) &&
          (c.domainOrPathLogin || c.domainOrPathVerify || hasWorkflowSignal || allKwCount >= 2);
        if (!hitHighRisk && !hitModerateRisk) return null;
        return {
          ruleId: 'combo_risky_tld_plus_lure',
          ruleName: 'Abused/Disposable TLD + Security or Credential Lure',
          category: 'indicatorCombinations',
          severity: 'high',
          indicatorStrength: 'strong',
          weight: c.w.comboRiskyTldPlusLure ?? 20,
          statusText: 'Flagged',
          label: `Elevated-risk TLD (.${c.domain.tld}) combined with credential/lure indicators`,
          explanation: 'Pairing higher-abuse TLDs with credential, verification, payment, or structurally obfuscated host patterns strongly signals phishing infrastructure.',
          evidence: `Domain ".${c.domain.tld}" pairs with ${allKwCount} lure keyword(s) or deceptive host signals.`,
        };
      },
    },
    {
      ruleId: 'combo_deceptive_host_lures',
      evaluate: (c) => {
        const domainKwCount = (c.domainKw && c.domainKw.length) || 0;
        const hasAffix =
          (c.domain.suspiciousDomainPrefixes && c.domain.suspiciousDomainPrefixes.length > 0) ||
          (c.domain.suspiciousDomainSuffixes && c.domain.suspiciousDomainSuffixes.length > 0);
        const denseSubLures =
          domainKwCount >= 4 ||
          (domainKwCount >= 3 && c.structure.nonWwwSubdomainCount >= 3) ||
          (domainKwCount >= 2 &&
            c.structure.nonWwwSubdomainCount >= 2 &&
            c.domainOrPathLogin &&
            c.domainOrPathVerify);
        const affixPlusWorkflow =
          hasAffix &&
          (c.pq.hasSuspiciousLoginFilename ||
            c.pq.hasFakeVerificationFilename ||
            c.pq.emailPrefillCount > 0 ||
            (c.domainOrPathLogin && c.domainOrPathVerify));
        const structuralHostDeceptionPlusLure =
          (c.domain.hasEmbeddedDomainInSubdomain || c.domain.hasLookalikeDigitSubstitution) &&
          (domainKwCount >= 1 ||
            c.domainOrPathLogin ||
            c.domainOrPathVerify ||
            c.domainOrPathRecovery ||
            c.pq.emailPrefillCount > 0 ||
            c.hasSuspensionLanguage);
        if (!denseSubLures && !affixPlusWorkflow && !structuralHostDeceptionPlusLure) return null;
        return {
          ruleId: 'combo_deceptive_host_lures',
          ruleName: 'Deceptive Multi-Signal Hostname & Credential Path',
          category: 'indicatorCombinations',
          severity: 'high',
          indicatorStrength: 'strong',
          weight: c.w.comboDeceptiveHostLures ?? 22,
          statusText: 'Flagged',
          label: 'Deceptive host structure combined with credential or authentication workflow terms',
          explanation: 'Combining misleading subdomain/character patterns with login or verification cues strongly indicates credential harvesting.',
          evidence: `Hostname "${c.features.hostname}" clusters structural deception with credential/trust signals.`,
        };
      },
    },
    {
      ruleId: 'combo_hidden_fragment_payload',
      evaluate: (c) => {
        if (!c.pq.fragmentRedirectOrEmailDetected) return null;
        const pairedSignal =
          c.domainOrPathLogin ||
          c.domainOrPathVerify ||
          c.domain.hasSuspiciousTld ||
          c.domain.suspiciousDomainPrefixes.length > 0 ||
          c.domain.suspiciousDomainSuffixes.length > 0 ||
          c.domain.hasEmbeddedDomainInSubdomain ||
          c.domain.hasLookalikeDigitSubstitution ||
          (c.domain.unrelatedEmbeddedDomains && c.domain.unrelatedEmbeddedDomains.length > 0);
        if (!pairedSignal) return null;
        return {
          ruleId: 'combo_hidden_fragment_payload',
          ruleName: 'Hidden Fragment Payload / Victim Prefill on Suspicious Link',
          category: 'indicatorCombinations',
          severity: 'high',
          indicatorStrength: 'strong',
          weight: c.w.comboHiddenFragmentPayload ?? 20,
          statusText: 'Flagged',
          label: 'Concealed fragment email prefill or encoded redirect paired with lure cues',
          explanation: 'Phishing links frequently embed target emails or Base64 redirect destinations after "#" to evade server-side inspection.',
          evidence: 'URL fragment contains an embedded destination URL or victim email prefill.',
        };
      },
    },
    {
      ruleId: 'combo_open_redirect_to_suspicious_target',
      evaluate: (c) =>
        c.pq.hasSuspiciousExternalRedirectTarget &&
        (c.pq.isOpenRedirectStructure || (c.pq.externalRedirectParams && c.pq.externalRedirectParams.length > 0)) && {
          ruleId: 'combo_open_redirect_to_suspicious_target',
          ruleName: 'External Redirect to High-Risk / Credential Target',
          category: 'indicatorCombinations',
          severity: 'high',
          indicatorStrength: 'strong',
          weight: c.w.comboRedirectSuspiciousTarget ?? 22,
          statusText: 'Detected',
          label: 'Redirect parameter forwards toward a high-risk external destination',
          explanation: 'Redirect endpoints forwarding visitors to disposable high-risk TLDs, raw IP hosts, or credential lures present phishing exposure.',
          evidence: `Redirect target "${(c.pq.externalRedirectParams[0] && c.pq.externalRedirectParams[0].targetHost) || 'external host'}" exhibits elevated risk indicators.`,
        },
    },
    {
      ruleId: 'combo_multiple_obfuscations',
      evaluate: (c) =>
        c.obfuscationTechniques >= 2 && {
          ruleId: 'combo_multiple_obfuscations',
          ruleName: 'Multiple URL Obfuscation Techniques Stacked',
          category: 'indicatorCombinations',
          severity: 'high',
          indicatorStrength: 'strong',
          weight: c.w.comboMultipleObfuscations ?? 26,
          statusText: 'Detected',
          label: `Multiple layered obfuscation techniques (${c.obfuscationTechniques} distinct methods)`,
          explanation: 'Combining multiple URL evasion techniques strongly indicates deliberate deception.',
          evidence: `Triggered ${c.obfuscationTechniques} independent manipulation/obfuscation signals simultaneously.`,
        },
    },
  ];

  function evaluateCategoryJ_Combinations(ctx) {
    const { structure, domain, patterns, pq, kw, scriptInfo, regInfo, th, w, features, push } = ctx;
    // =========================================================================
    // CATEGORY J: Multi-Indicator Combination Rules (Correlated Patterns)
    // =========================================================================
    const domainKw = (kw.byLocation && kw.byLocation.domain) || [];
    const domainOrPathLogin =
      (kw.byCategory && kw.byCategory.credential.some((x) => ['login', 'signin', 'sign-in', 'logon', 'auth', 'authentication'].includes(x))) ||
      pq.hasSuspiciousLoginFilename;
    const domainOrPathVerify =
      (kw.byCategory && kw.byCategory.recovery.some((x) => ['verify', 'verification', 'validate', 'confirm', 'confirmation'].includes(x))) ||
      pq.hasFakeVerificationFilename;
    const domainOrPathRecovery =
      (kw.byCategory && kw.byCategory.recovery.some((x) => ['reset', 'recover', 'recovery', 'unlock'].includes(x))) ||
      pq.hasPasswordResetPath;
    const hasSuspensionLanguage = Boolean(kw.byCategory && kw.byCategory.urgency.length > 0);

    const hasPathEncodedDelimiter =
      patterns.hasEncodedDotOrSlashInPath !== undefined
        ? patterns.hasEncodedDotOrSlashInPath
        : (patterns.hasEncodedSlash || patterns.hasEncodedDot);

    const obfuscationTechniques = [
      patterns.hasAtInAuthority || patterns.hasEncodedAt,
      patterns.hasDoubleEncoding,
      hasPathEncodedDelimiter,
      patterns.hasHexEscapeInAuthority || structure.hasObfuscatedIp,
      patterns.hasBackslash,
      patterns.hasBidiChars || patterns.hasInvisibleUnicode,
      scriptInfo.hasMixedScriptsInLabel,
      pq.nestedRedirectCount > 0 || pq.encodedExternalRedirectCount > 0,
      patterns.hasDoubleSlashAfterHost,
      patterns.nonSpaceEncodedCount >= th.nonSpaceEncodedHeavy,
    ].filter(Boolean).length;

    const comboCtx = {
      features,
      structure,
      domain,
      patterns,
      pq,
      kw,
      scriptInfo,
      regInfo,
      th,
      w,
      domainKw,
      domainOrPathLogin,
      domainOrPathVerify,
      domainOrPathRecovery,
      hasSuspensionLanguage,
      obfuscationTechniques,
    };

    for (let i = 0; i < COMBO_RULE_DEFINITIONS.length; i++) {
      const triggered = COMBO_RULE_DEFINITIONS[i].evaluate(comboCtx);
      if (triggered) {
        push(triggered);
      }
    }

    ctx.obfuscationTechniques = obfuscationTechniques;
  }

  const CENTRAL_RULE_PIPELINE = [
    { ...REGISTERED_PIPELINE_STAGES[0], run: evaluateCategoryA_UrlComplexity },
    { ...REGISTERED_PIPELINE_STAGES[1], run: evaluateCategoryB_CharManipulation },
    { ...REGISTERED_PIPELINE_STAGES[2], run: evaluateCategoryC_HostStructure },
    { ...REGISTERED_PIPELINE_STAGES[3], run: evaluateCategoryD_BrandImpersonation },
    { ...REGISTERED_PIPELINE_STAGES[4], run: evaluateCategoryE_LureKeywords },
    { ...REGISTERED_PIPELINE_STAGES[5], run: evaluateCategoryF_PathAndQuery },
    { ...REGISTERED_PIPELINE_STAGES[6], run: evaluateCategoryG_RedirectPatterns },
    { ...REGISTERED_PIPELINE_STAGES[7], run: evaluateCategoryH_TransportAndProtocol },
    { ...REGISTERED_PIPELINE_STAGES[8], run: evaluateCategoryI_DomainReputation },
    { ...REGISTERED_PIPELINE_STAGES[9], run: evaluatePageContextRules },
    { ...REGISTERED_PIPELINE_STAGES[10], run: evaluateCategoryJ_Combinations },
  ];

  function getRegisteredPipelineStages() {
    return REGISTERED_PIPELINE_STAGES.map((stage) => ({ ...stage }));
  }

  function evaluateRules(features, context, customConfig) {
    if (!features || !features.valid) {
      return {
        rules: [],
        triggeredIds: new Set(),
        obfuscationTechniques: 0,
        pipelineStagesExecuted: [],
      };
    }

    const ctx = createRuleContext(features, context, customConfig);
    const pipelineStagesExecuted = [];

    for (let i = 0; i < CENTRAL_RULE_PIPELINE.length; i++) {
      const stage = CENTRAL_RULE_PIPELINE[i];
      stage.run(ctx);
      pipelineStagesExecuted.push(stage.stageId);
    }

    return {
      rules: ctx.rules,
      triggeredIds: ctx.triggeredIds,
      obfuscationTechniques: ctx.obfuscationTechniques || 0,
      pipelineStagesExecuted,
    };
  }

  return {
    CATEGORY_LABELS,
    DEFAULT_RULE_THRESHOLDS,
    COMBO_RULE_DEFINITIONS,
    getRegisteredPipelineStages,
    evaluateRules,
  };
});
