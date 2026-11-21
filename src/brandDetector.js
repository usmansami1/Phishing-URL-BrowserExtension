/**
 * PhishGuard - Unicode, Punycode & Structural Obfuscation Utilities
 * Purely algorithmic, brand-free analysis for Punycode decoding (RFC 3492),
 * Unicode confusable normalization, mixed-script detection, keyword
 * substitution normalization, and mid-word digit-substitution detection.
 *
 * Uses NO stored URL lists, brand databases, or domain whitelists/blacklists.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  }
  root.PhishGuardBrandDetector = api;
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

  // Cyrillic, Greek, and extended Latin characters that visually resemble ASCII letters
  const CONFUSABLE_MAP = {
    // Cyrillic
    '\u0430': 'a', '\u0410': 'a', // а
    '\u0432': 'b', '\u0412': 'b', // в
    '\u0435': 'e', '\u0415': 'e', // е
    '\u0451': 'e', '\u0401': 'e', // ё
    '\u043a': 'k', '\u041a': 'k', // к
    '\u043c': 'm', '\u041c': 'm', // м
    '\u043d': 'h', '\u041d': 'h', // н
    '\u043e': 'o', '\u041e': 'o', // о
    '\u0440': 'p', '\u0420': 'p', // р
    '\u0441': 'c', '\u0421': 'c', // с
    '\u0442': 't', '\u0422': 't', // т
    '\u0443': 'y', '\u0423': 'y', // у
    '\u0445': 'x', '\u0425': 'x', // х
    '\u0456': 'i', '\u0406': 'i', // і
    '\u0458': 'j', '\u0408': 'j', // ј
    '\u0455': 's', '\u0405': 's', // ѕ
    '\u0501': 'd', '\u0500': 'd', // ԁ
    '\u04bb': 'h', '\u04ba': 'h', // һ
    '\u051b': 'q',                // ԛ
    '\u051d': 'w',                // ԝ
    // Greek
    '\u03b1': 'a', '\u0391': 'a', // α
    '\u03b2': 'b', '\u0392': 'b', // β
    '\u03b5': 'e', '\u0395': 'e', // ε
    '\u03b6': 'z', '\u0396': 'z', // ζ
    '\u03b7': 'n', '\u0397': 'h', // η
    '\u03b9': 'i', '\u0399': 'i', // ι
    '\u03ba': 'k', '\u039a': 'k', // κ
    '\u03bc': 'm', '\u039c': 'm', // μ
    '\u03bd': 'v', '\u039d': 'n', // ν
    '\u03bf': 'o', '\u039f': 'o', // ο
    '\u03c1': 'p', '\u03a1': 'p', // ρ
    '\u03c4': 't', '\u03a4': 't', // τ
    '\u03c5': 'u', '\u03a5': 'y', // υ
    '\u03c7': 'x', '\u03a7': 'x', // χ
    // Latin dotless / extended lookalikes
    '\u0131': 'i', // ı
    '\u0261': 'g', // ɡ
    '\u217c': 'l', // ⅼ
    '\u2174': 'v', // ⅴ
  };

  const LOOKALIKE_DIGIT_HINTS = {
    '0': 'o',
    '1': 'l/i',
    '3': 'e',
    '4': 'a',
    '5': 's',
  };

  // RFC 3492 Punycode label decoder
  function decodePunycodeLabel(label) {
    if (typeof label !== 'string' || !label.toLowerCase().startsWith('xn--')) {
      return label;
    }
    const input = label.slice(4);
    const base = 36;
    const tMin = 1;
    const tMax = 26;
    const skew = 38;
    const damp = 700;
    const initialBias = 72;
    const initialN = 128;

    let n = initialN;
    let i = 0;
    let bias = initialBias;
    const output = [];

    const delimIndex = input.lastIndexOf('-');
    let pos = 0;
    if (delimIndex > 0) {
      for (let j = 0; j < delimIndex; j++) {
        output.push(input.charCodeAt(j));
      }
      pos = delimIndex + 1;
    }

    function adapt(delta, numPoints, firstTime) {
      let d = firstTime ? Math.floor(delta / damp) : delta >> 1;
      d += Math.floor(d / numPoints);
      let k = 0;
      while (d > ((base - tMin) * tMax) >> 1) {
        d = Math.floor(d / (base - tMin));
        k += base;
      }
      return k + Math.floor(((base - tMin + 1) * d) / (d + skew));
    }

    function digitFromChar(code) {
      if (code >= 48 && code <= 57) return code - 22;
      if (code >= 65 && code <= 90) return code - 65;
      if (code >= 97 && code <= 122) return code - 97;
      return 36;
    }

    try {
      while (pos < input.length) {
        const oldi = i;
        let w = 1;
        for (let k = base; ; k += base) {
          if (pos >= input.length) return label;
          const digit = digitFromChar(input.charCodeAt(pos++));
          if (digit >= base) return label;
          i += digit * w;
          const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
          if (digit < t) break;
          w *= base - t;
        }
        const outLen = output.length + 1;
        bias = adapt(i - oldi, outLen, oldi === 0);
        n += Math.floor(i / outLen);
        i %= outLen;
        output.splice(i, 0, n);
        i++;
      }
      return String.fromCodePoint(...output);
    } catch (_) {
      return label;
    }
  }

  function decodePunycodeDomain(hostname) {
    if (!hostname) return '';
    return hostname
      .split('.')
      .map((lbl) => decodePunycodeLabel(lbl))
      .join('.');
  }

  function normalizeUnicodeConfusables(str) {
    if (!str) return { ascii: '', hadConfusable: false, hadDiacriticOrNonAscii: false };
    const rawStr = String(str);
    const nfdRaw = rawStr.normalize('NFD');
    const decomposed = nfdRaw.replace(/[\u0300-\u036f]/g, '');
    const hadDiacritics = decomposed !== nfdRaw || /[^\x00-\x7f]/.test(rawStr);
    let out = '';
    let hadConfusable = false;

    for (const ch of decomposed) {
      if (CONFUSABLE_MAP[ch]) {
        out += CONFUSABLE_MAP[ch];
        hadConfusable = true;
      } else {
        const lower = ch.toLowerCase();
        if (/[^\x00-\x7f]/.test(lower)) {
          hadConfusable = true;
        }
        out += lower;
      }
    }
    return {
      ascii: out,
      hadConfusable,
      hadDiacriticOrNonAscii: hadConfusable || hadDiacritics,
    };
  }

  function detectUnicodeScripts(hostname) {
    const clean = String(hostname || '');
    const labels = clean.split('.').filter(Boolean);
    const allScripts = new Set();
    const mixedLabels = [];
    let hasNonAscii = false;

    for (let i = 0; i < labels.length; i++) {
      const labelScripts = new Set();
      const decomposed = labels[i].normalize('NFD').replace(/[\u0300-\u036f]/g, '');
      for (const ch of decomposed) {
        if (/^[a-zA-Z]$/.test(ch) || (ch >= '\u00C0' && ch <= '\u024F')) {
          labelScripts.add('Latin');
        } else if (/^[\u0400-\u052F]$/.test(ch)) {
          labelScripts.add('Cyrillic');
          hasNonAscii = true;
        } else if (/^[\u0370-\u03FF]$/.test(ch)) {
          labelScripts.add('Greek');
          hasNonAscii = true;
        } else if (/[^\x00-\x7f]/.test(ch)) {
          labelScripts.add('NonLatin');
          hasNonAscii = true;
        }
      }
      labelScripts.forEach((s) => allScripts.add(s));
      if (labelScripts.size >= 2) {
        mixedLabels.push({ label: labels[i], scripts: Array.from(labelScripts) });
      }
    }

    return {
      scripts: Array.from(allScripts),
      mixedLabels,
      hasMixedScriptsInLabel: mixedLabels.length > 0,
      hasMixedScriptsAcrossHost: allScripts.size >= 2,
      hasNonAsciiScript: hasNonAscii || /[^\x00-\x7f]/.test(clean),
    };
  }

  function buildSubstitutionVariants(token) {
    const clean = String(token || '').toLowerCase();
    const base = clean
      .replace(/0/g, 'o')
      .replace(/3/g, 'e')
      .replace(/4/g, 'a')
      .replace(/5/g, 's')
      .replace(/6/g, 'g')
      .replace(/7/g, 't')
      .replace(/8/g, 'b')
      .replace(/9/g, 'g')
      .replace(/@/g, 'a')
      .replace(/\$/g, 's')
      .replace(/!/g, 'i')
      .replace(/rn/g, 'm')
      .replace(/vv/g, 'w')
      .replace(/ii/g, 'u');

    const variants = new Set([
      base.replace(/1/g, 'l'),
      base.replace(/1/g, 'i'),
      base.replace(/1/g, 'l').replace(/cl/g, 'd'),
      base.replace(/1/g, 'i').replace(/cl/g, 'd'),
      base.replace(/1/g, 'l').replace(/nn/g, 'm'),
    ]);
    variants.delete(clean);
    return Array.from(variants);
  }

  function damerauLevenshtein(a, b) {
    if (a === b) return 0;
    const alen = a.length;
    const blen = b.length;
    if (!alen) return blen;
    if (!blen) return alen;

    const d = Array.from({ length: alen + 1 }, () => new Array(blen + 1).fill(0));
    for (let i = 0; i <= alen; i++) d[i][0] = i;
    for (let j = 0; j <= blen; j++) d[0][j] = j;

    for (let i = 1; i <= alen; i++) {
      for (let j = 1; j <= blen; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        let val = Math.min(
          d[i - 1][j] + 1,
          d[i][j - 1] + 1,
          d[i - 1][j - 1] + cost
        );
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
          val = Math.min(val, d[i - 2][j - 2] + 1);
        }
        d[i][j] = val;
      }
    }
    return d[alen][blen];
  }

  /**
   * Detect structural lookalike digit-for-letter substitutions within host tokens
   * without comparing against any stored brand or URL list:
   * - Medial substitution: lookalike digit(s) (0/1/3/4/5) embedded mid-word
   *   between ASCII letters (e.g., "g00gle", "amaz0n", "qa1am", "m1crosoft").
   * - Boundary substitution: single isolated lookalike digit attached directly at
   *   the start/end of a long alphabetic stem without hyphen separation
   *   (e.g., "paypa1", "wellsfarg0", "0utlook"), excluding multi-digit suffixes
   *   ("shop24", "base64") and short tech tokens ("web3", "v1", "ipv4", "a11y").
   */
  function detectDigitSubstitutions(domainParts) {
    const labelsToInspect = [];
    if (domainParts && domainParts.sld) {
      labelsToInspect.push(String(domainParts.sld).toLowerCase());
    }
    if (domainParts && Array.isArray(domainParts.nonWwwSubdomains)) {
      for (let i = 0; i < domainParts.nonWwwSubdomains.length; i++) {
        labelsToInspect.push(String(domainParts.nonWwwSubdomains[i]).toLowerCase());
      }
    }

    const medialMatches = [];
    const boundaryMatches = [];
    const seenMedial = new Set();
    const seenBoundary = new Set();

    for (let li = 0; li < labelsToInspect.length; li++) {
      const label = labelsToInspect[li];
      if (!label || label.startsWith('xn--')) continue;

      const tokens = label.split(/[-_]+/).filter(Boolean);
      for (let ti = 0; ti < tokens.length; ti++) {
        const tok = tokens[ti];
        if (tok.length < 5 || !/^[a-z0-9]+$/.test(tok)) continue;

        const parts = tok.match(/[a-z]+|\d+/g) || [];
        let letterCount = 0;
        const medialHitsInToken = [];

        for (let pi = 0; pi < parts.length; pi++) {
          if (/^[a-z]+$/.test(parts[pi])) {
            letterCount += parts[pi].length;
          } else if (
            pi > 0 &&
            pi < parts.length - 1 &&
            /^(0|00|1|11|3|33|4|44|5|55)$/.test(parts[pi]) &&
            /^[a-z]+$/.test(parts[pi - 1]) &&
            /^[a-z]+$/.test(parts[pi + 1])
          ) {
            medialHitsInToken.push({
              digits: parts[pi],
              leftLetters: parts[pi - 1],
              rightLetters: parts[pi + 1],
              letterHint: LOOKALIKE_DIGIT_HINTS[parts[pi][0]] || 'letter',
            });
          }
        }

        const enoughLetters =
          letterCount >= 4 || (medialHitsInToken.length >= 2 && letterCount >= 3);

        if (medialHitsInToken.length > 0 && enoughLetters) {
          if (!seenMedial.has(tok)) {
            seenMedial.add(tok);
            medialMatches.push({
              token: tok,
              label,
              substitutions: medialHitsInToken,
            });
          }
          continue;
        }

        // Single-transition word-boundary lookalike substitution (e.g. "paypa1", "wellsfarg0", "0utlook")
        const trailing01 = tok.match(/^([a-z]{4,})([01])$/);
        const trailing345 = tok.match(/^([a-z]{5,})([345])$/);
        const leading01 = tok.match(/^([01])([a-z]{4,})$/);
        const boundaryMatch = trailing01 || trailing345 || leading01;
        if (boundaryMatch && !seenBoundary.has(tok)) {
          seenBoundary.add(tok);
          const isLeading = Boolean(leading01);
          const digit = isLeading ? boundaryMatch[1] : boundaryMatch[2];
          const stem = isLeading ? boundaryMatch[2] : boundaryMatch[1];
          boundaryMatches.push({
            token: tok,
            label,
            position: isLeading ? 'leading' : 'trailing',
            digits: digit,
            stem,
            letterHint: LOOKALIKE_DIGIT_HINTS[digit] || 'letter',
          });
        }
      }
    }

    return {
      medial: { detected: medialMatches.length > 0, matches: medialMatches },
      boundary: { detected: boundaryMatches.length > 0, matches: boundaryMatches },
      hasAnyLookalike: medialMatches.length > 0 || boundaryMatches.length > 0,
    };
  }

  function detectMedialDigitSubstitution(domainParts) {
    return detectDigitSubstitutions(domainParts).medial;
  }

  /**
   * Purely algorithmic, rule-based host lookalike & script analyzer.
   * Performs Unicode/Punycode decoding, script analysis, confusable detection,
   * and digit-substitution checks with zero stored URLs or brands.
   */
  function analyzeHostLookalikes(params) {
    const p = params || {};
    const domainParts = p.domainParts || {};
    const rawHost = p.rawHost || domainParts.hostname || '';

    const rawSld = (domainParts.sld || '').toLowerCase();
    const rawSubdomainStr = (domainParts.subdomainStr || '').toLowerCase();

    const decodedHost = decodePunycodeDomain(domainParts.hostname || rawHost);
    const decodedRawHost = /[^\x00-\x7f]/.test(rawHost) ? rawHost : decodedHost;
    const decodedSld = decodePunycodeDomain(rawSld);
    const decodedSubdomains = decodePunycodeDomain(rawSubdomainStr);

    const sldConfusable = normalizeUnicodeConfusables(decodedSld);
    const subConfusable = normalizeUnicodeConfusables(decodedSubdomains);
    const scriptInfo = detectUnicodeScripts(decodedRawHost);
    const digitSubs = detectDigitSubstitutions(domainParts);

    return {
      decodedHost: decodedRawHost,
      scriptInfo,
      hasConfusableCharsInHost: sldConfusable.hadConfusable || subConfusable.hadConfusable,
      medialDigitSubstitutions: digitSubs.medial,
      boundaryDigitSubstitutions: digitSubs.boundary,
      hasMedialDigitSubstitution: digitSubs.medial.detected,
      hasBoundaryDigitSubstitution: digitSubs.boundary.detected,
      hasLookalikeDigitSubstitution: digitSubs.hasAnyLookalike,
    };
  }

  return {
    decodePunycodeLabel,
    decodePunycodeDomain,
    normalizeUnicodeConfusables,
    detectUnicodeScripts,
    buildSubstitutionVariants,
    damerauLevenshtein,
    detectMedialDigitSubstitution,
    detectDigitSubstitutions,
    analyzeHostLookalikes,
    detectBrandImpersonation: analyzeHostLookalikes,
  };
});
