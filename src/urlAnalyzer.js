/**
 * PhishGuard - URL Extraction & Comprehensive Feature Analysis Module
 * Parses, normalizes (preserving raw obfuscation evidence), and extracts
 * layered security features across structure, encoding, host, PSL domain,
 * brand impersonation, keyword semantics, path/query, redirects, and protocol.
 */
(function (root, factory) {
  let brandDetector = root.PhishGuardBrandDetector;
  if (typeof module === 'object' && module.exports && !brandDetector) {
    brandDetector = require('./brandDetector.js');
  }
  const api = factory(brandDetector);
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  }
  root.PhishGuardURLAnalyzer = api;
})(typeof globalThis !== 'undefined' ? globalThis : self, function (BrandDetector) {
  'use strict';

  const SUPPORTED_PROTOCOLS = new Set(['http:', 'https:']);

  // Chromium / Chrome component extension ID for the built-in PDFium viewer
  const CHROME_PDF_VIEWER_EXTENSION_ID = 'mhjfbmdgcfjbbpaeojofohoefgiehjai';

  const EXEMPT_DIRECT_SCHEMES = new Set([
    'chrome:',
    'chrome-extension:',
    'extension:',
    'chrome-search:',
    'chrome-devtools:',
    'chrome-untrusted:',
    'devtools:',
    'edge:',
    'brave:',
    'opera:',
    'vivaldi:',
    'about:',
    'file:',
  ]);

  const NESTED_WRAPPER_PREFIXES = ['blob:', 'filesystem:', 'view-source:'];

  const UNSUPPORTED_PREFIXES = [
    'chrome://',
    'chrome-extension://',
    'extension://',
    'chrome-search://',
    'chrome-devtools://',
    'chrome-untrusted://',
    'devtools://',
    'edge://',
    'brave://',
    'opera://',
    'vivaldi://',
    'about:',
    'view-source:',
    'data:',
    'blob:',
    'javascript:',
    'file://',
  ];

  // Public Suffix List-aware multi-part public suffixes
  const MULTI_PART_SUFFIXES = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'ltd.uk', 'plc.uk', 'nhs.uk', 'police.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'ad.jp', 'ed.jp', 'go.jp', 'gr.jp', 'lg.jp',
    'co.kr', 'ne.kr', 'or.kr', 're.kr', 'pe.kr', 'go.kr', 'mil.kr', 'ac.kr',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
    'com.hk', 'edu.hk', 'gov.hk', 'idv.hk', 'net.hk', 'org.hk',
    'com.tw', 'edu.tw', 'gov.tw', 'idv.tw', 'net.tw', 'org.tw',
    'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'mil.br',
    'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in', 'ac.in', 'edu.in', 'res.in', 'gov.in',
    'com.pk', 'net.pk', 'edu.pk', 'org.pk', 'gov.pk', 'fam.pk', 'biz.pk', 'web.pk',
    'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz', 'school.nz', 'maori.nz',
    'co.za', 'org.za', 'net.za', 'gov.za', 'ac.za', 'edu.za', 'web.za',
    'com.mx', 'net.mx', 'org.mx', 'edu.mx', 'gob.mx',
    'com.tr', 'net.tr', 'org.tr', 'edu.tr', 'gov.tr', 'biz.tr', 'info.tr',
    'com.sg', 'net.sg', 'org.sg', 'edu.sg', 'gov.sg', 'per.sg',
    'com.ar', 'net.ar', 'org.ar', 'gov.ar', 'edu.ar',
    'com.my', 'net.my', 'org.my', 'edu.my', 'gov.my',
    'co.id', 'or.id', 'ac.id', 'go.id', 'web.id', 'sch.id',
    'co.th', 'in.th', 'ac.th', 'go.th', 'or.th', 'net.th',
    'com.vn', 'net.vn', 'org.vn', 'edu.vn', 'gov.vn',
    'com.ph', 'net.ph', 'org.ph', 'edu.ph', 'gov.ph',
    'co.il', 'org.il', 'net.il', 'ac.il', 'gov.il', 'muni.il',
    'com.sa', 'net.sa', 'org.sa', 'edu.sa', 'gov.sa',
    'com.eg', 'net.eg', 'org.eg', 'edu.eg', 'gov.eg',
    'com.ng', 'net.ng', 'org.ng', 'edu.ng', 'gov.ng',
    'co.ke', 'or.ke', 'ac.ke', 'go.ke',
    'com.ua', 'net.ua', 'org.ua', 'edu.ua', 'gov.ua',
    'com.pl', 'net.pl', 'org.pl', 'edu.pl', 'gov.pl',
    'co.cr', 'or.cr', 'ac.cr', 'go.cr',
    'com.co', 'net.co', 'org.co', 'edu.co', 'gov.co',
    'com.pe', 'net.pe', 'org.pe', 'edu.pe', 'gob.pe',
    'com.ve', 'net.ve', 'org.ve', 'edu.ve', 'gob.ve',
    'gc.ca', 'gouv.fr', 'gouv.qc.ca',
    'eu.org', 'us.com', 'uk.com', 'de.com', 'br.com', 'cn.com', 'jpn.com', 'sa.com',
  ]);

  // Tiered TLD extension signals (structural extension risk, never specific domains)
  const HIGH_RISK_TLDS = new Set([
    'tk', 'ml', 'ga', 'cf', 'gq', 'cfd', 'sbs', 'top', 'icu', 'buzz',
    'zip', 'mov', 'click', 'work', 'loan', 'win', 'bid', 'review',
    'country', 'stream', 'download', 'gdn', 'racing', 'party', 'accountant',
    'science', 'xin', 'fit', 'rest', 'quest', 'cyou', 'surf', 'cam', 'kim',
    'bar', 'bond', 'boats', 'autos', 'homes', 'lat',
  ]);

  const MODERATE_RISK_TLDS = new Set([
    'xyz', 'club', 'online', 'site', 'live', 'life', 'vip', 'shop', 'info',
    'support', 'store', 'fun', 'space', 'website', 'tech', 'monster', 'uno',
    'pw', 'cc', 'ws', 'su', 'ru', 'cn', 'ink',
  ]);

  // Comprehensive Categorized Keywords (Category E)
  const KEYWORD_GROUPS = {
    credential: [
      'login', 'signin', 'sign-in', 'logon', 'authentication', 'auth',
      'password', 'passcode', 'credential', 'credentials', 'otp', 'pin',
      'webscr', 'session', 'identity', 'access', 'sso', 'oauth',
    ],
    recovery: [
      'verify', 'verification', 'validate', 'validation', 'confirm', 'confirmation',
      'update', 'reset', 'recover', 'recovery', 'unlock', 'reactivate', 'kyc',
    ],
    urgency: [
      'suspended', 'suspend', 'restricted', 'restrict', 'locked', 'urgent',
      'expired', 'expire', 'unusual', 'limited', 'alert',
    ],
    payment: [
      'banking', 'bank', 'payment', 'payments', 'billing', 'invoice', 'wallet',
      'card', 'credit', 'debit', 'transaction', 'refund', 'checkout', 'seedphrase',
    ],
    securityTrust: [
      'secure', 'security', 'account', 'accounts', 'support', 'helpdesk',
      'admin', 'customer', 'delivery', 'tracking', 'document', 'shared',
      'invitation', 'notification', 'portal', 'service', 'official', 'https', 'ssl',
    ],
  };

  // Backwards-compatible subsets
  const CREDENTIAL_KEYWORDS = [
    ...KEYWORD_GROUPS.credential,
    ...KEYWORD_GROUPS.recovery,
    ...KEYWORD_GROUPS.urgency,
    'wallet',
  ];

  const SECURITY_TRUST_KEYWORDS = [
    ...KEYWORD_GROUPS.payment,
    ...KEYWORD_GROUPS.securityTrust,
  ];

  const HOST_AFFIX_WORDS = [
    'secure', 'login', 'signin', 'account', 'accounts', 'verify', 'verification',
    'update', 'confirm', 'auth', 'support', 'helpdesk', 'billing', 'unlock',
    'reset', 'recover', 'security',
  ];

  const REDIRECT_PARAM_NAMES = new Set([
    'redirect', 'redirect_uri', 'redirect_url', 'redir', 'next', 'return',
    'return_to', 'returnto', 'continue', 'dest', 'destination', 'callback',
    'cb', 'target', 'goto', 'out', 'forward', 'url', 'u', 'link', 'ref',
    'jump', 'to', 'r', 'q',
  ]);

  const OPEN_REDIRECT_PATH_SEGMENTS = new Set([
    'redirect', 'redir', 'out', 'go', 'away', 'bounce', 'forward',
    'exit', 'external', 'url', 'jump', 'transfer',
  ]);

  const EXECUTABLE_EXTENSIONS = new Set([
    'exe', 'msi', 'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'scr', 'jar',
    'apk', 'hta', 'lnk', 'iso', 'img', 'com', 'pif', 'reg', 'dmg', 'pkg',
  ]);

  const ARCHIVE_EXTENSIONS = new Set([
    'zip', 'rar', '7z', 'tar', 'gz', 'cab',
  ]);

  const SCRIPT_EXTENSIONS = new Set([
    'php', 'cgi', 'pl', 'asp', 'aspx', 'jsp', 'jspx',
  ]);

  const SPECIAL_CHAR_REGEX = /[@?=&#%_+~!$*,;:'"()[\]{}|\\<>^`]/g;
  const PUNCTUATION_REGEX = /[.\-_/?=&%@!~*+;:,'"`\\|[\]{}()<>^#$]/g;
  const BIDI_CHAR_REGEX = /[\u200E\u200F\u202A-\u202E\u2066-\u2069\u061C]/;
  const INVISIBLE_UNICODE_REGEX = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/;

  function extractSchemeHost(candidateLower) {
    const match = candidateLower.match(/^[a-z][a-z\d+\-.]*:\/\/([^/?#]*)/);
    return match ? match[1] : '';
  }

  /**
   * Inspects the leading URL scheme before normalization/feature extraction to distinguish
   * browser-internal pages, extension/built-in PDF viewer frames, and local files from
   * external http/https websites (including external websites serving .pdf files).
   */
  function classifyExemptUrl(rawUrl) {
    const emptyMeta = {
      isExempt: false,
      isInternalBrowserPage: false,
      isPdfViewer: false,
      isLocalFile: false,
      scheme: '',
      category: 'web',
      reason: '',
    };
    if (typeof rawUrl !== 'string') return emptyMeta;
    const trimmed = rawUrl.trim();
    if (!trimmed) return emptyMeta;

    const lower = trimmed.toLowerCase();
    const schemeMatch = lower.match(/^([a-z][a-z\d+\-.]*):/);
    if (!schemeMatch) {
      return emptyMeta;
    }

    const scheme = `${schemeMatch[1]}:`;
    // Fast path: external web URLs (including http(s)://.../*.pdf) are NEVER exempt.
    if (SUPPORTED_PROTOCOLS.has(scheme)) {
      return { ...emptyMeta, scheme };
    }

    if (EXEMPT_DIRECT_SCHEMES.has(scheme)) {
      const host = extractSchemeHost(lower);
      const isExtScheme = scheme === 'chrome-extension:' || scheme === 'extension:';
      const isPdfViewerExt = isExtScheme && host === CHROME_PDF_VIEWER_EXTENSION_ID;
      const isEdgePdf = scheme === 'edge:' && (host === 'pdf' || lower.startsWith('edge://pdf/'));
      const isLocalFile = scheme === 'file:';
      const isPdfViewer = isPdfViewerExt || isEdgePdf;

      let category = 'browser_internal';
      let reason = 'Internal browser pages are excluded from website phishing scanning.';
      if (isPdfViewer) {
        category = 'pdf_viewer';
        reason = "Chrome/browser built-in PDF viewer pages are exempt from website phishing scanning.";
      } else if (isLocalFile) {
        category = 'local_file';
        reason = 'Local file:// documents are exempt from external website phishing scanning.';
      } else if (isExtScheme) {
        category = 'extension';
        reason = 'Browser extension pages are excluded from external website phishing scanning.';
      }

      return {
        isExempt: true,
        isInternalBrowserPage: true,
        isPdfViewer,
        isLocalFile,
        scheme,
        category,
        reason,
      };
    }

    for (let i = 0; i < NESTED_WRAPPER_PREFIXES.length; i++) {
      const prefix = NESTED_WRAPPER_PREFIXES[i];
      if (lower.startsWith(prefix)) {
        const inner = trimmed.slice(prefix.length);
        const innerMeta = classifyExemptUrl(inner);
        if (innerMeta.isExempt) {
          return {
            ...innerMeta,
            scheme,
          };
        }
        return { ...emptyMeta, scheme };
      }
    }

    return { ...emptyMeta, scheme };
  }

  function isSupportedUrl(rawUrl) {
    if (typeof rawUrl !== 'string') return false;
    const trimmed = rawUrl.trim();
    if (!trimmed) return false;
    if (classifyExemptUrl(trimmed).isExempt) {
      return false;
    }
    const lower = trimmed.toLowerCase();
    for (let i = 0; i < UNSUPPORTED_PREFIXES.length; i++) {
      if (lower.startsWith(UNSUPPORTED_PREFIXES[i])) {
        return false;
      }
    }
    const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z\d+\-.]*):/);
    if (schemeMatch && !SUPPORTED_PROTOCOLS.has(schemeMatch[1].toLowerCase() + ':')) {
      return false;
    }
    const parsed = normalizeUrl(trimmed);
    if (!parsed) return false;
    if (!schemeMatch) {
      const host = parsed.hostname.toLowerCase();
      const rawHostSlice = parseRawSlices(trimmed).rawHost;
      const hasRawIp = /^\d+$/.test(rawHostSlice) || /^0x[0-9a-f]/i.test(rawHostSlice);
      if (host !== 'localhost' && !host.includes('.') && !host.includes(':') && !hasRawIp) {
        return false;
      }
    }
    return SUPPORTED_PROTOCOLS.has(parsed.protocol.toLowerCase());
  }

  function safeDecode(value) {
    if (typeof value !== 'string') return '';
    try {
      return decodeURIComponent(value);
    } catch (_) {
      return value;
    }
  }

  function safeMultiDecode(value, rounds = 2) {
    let cur = String(value || '');
    for (let i = 0; i < rounds; i++) {
      const next = safeDecode(cur);
      if (next === cur) break;
      cur = next;
    }
    return cur;
  }

  function tryDecodeBase64UrlPrefix(value) {
    const raw = String(value || '').trim();
    if (!/^aHR0c/i.test(raw) || raw.length < 10) return '';
    try {
      if (typeof atob === 'function') {
        const normalized = raw.replace(/-/g, '+').replace(/_/g, '/');
        const decoded = atob(normalized);
        if (/^https?:\/\//i.test(decoded)) {
          return decoded;
        }
      }
    } catch (_) {
      // Ignore invalid base64
    }
    return '';
  }

  function normalizeUrl(rawUrl) {
    if (typeof rawUrl !== 'string') return null;
    const trimmed = rawUrl.trim();
    if (!trimmed) return null;

    let candidate = trimmed;
    if (!/^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(candidate)) {
      if (candidate.startsWith('//')) {
        candidate = 'https:' + candidate;
      } else {
        candidate = 'https://' + candidate;
      }
    }

    // Decode percent-encoded '@' (%40) inside raw authority so WHATWG URL still parses
    // obfuscated authority traps (e.g. decoy.example%40target.example/login) cleanly.
    const authSplit = candidate.match(/^([a-zA-Z][a-zA-Z\d+\-.]*:\/\/)([^/?#]*)(.*)$/);
    if (authSplit && /%40/i.test(authSplit[2])) {
      candidate = authSplit[1] + authSplit[2].replace(/%40/gi, '@') + authSplit[3];
    }

    try {
      const urlObj = new URL(candidate);
      if (!SUPPORTED_PROTOCOLS.has(urlObj.protocol.toLowerCase())) {
        return null;
      }
      if (!urlObj.hostname) return null;
      return urlObj;
    } catch (_) {
      return null;
    }
  }

  function parseRawSlices(rawUrl) {
    const trimmed = String(rawUrl || '');
    const schemeMatch = trimmed.match(/^\s*([a-zA-Z][a-zA-Z\d+\-.]*):(\/\/)?/);
    const rawScheme = schemeMatch ? schemeMatch[1] : '';
    const afterScheme = schemeMatch
      ? trimmed.slice(schemeMatch[0].length)
      : trimmed.replace(/^\/+/, '');
    const authMatch = afterScheme.match(/^(?:([^/?#@]+)@)?([^/?#]*)/);
    const rawUserInfo = authMatch && authMatch[1] ? authMatch[1] : '';
    const rawHostAndPort = authMatch && authMatch[2] ? authMatch[2] : '';
    const rawHost = rawHostAndPort.replace(/:\d+$/, '').toLowerCase();
    const rawAfterAuthority = afterScheme.slice(authMatch ? authMatch[0].length : 0);
    const rawAuthority = rawUserInfo ? `${rawUserInfo}@${rawHostAndPort}` : rawHostAndPort;

    const isRawNumeric = /^\d+$/.test(rawHost);
    const isHexOrOctalIp =
      /^(0x[0-9a-f]+|0[0-7]+)(\.(0x[0-9a-f]+|0[0-7]+|\d+)){1,3}$/i.test(rawHost) ||
      /^0x[0-9a-f]{6,}$/i.test(rawHost);

    return {
      trimmed,
      rawScheme,
      rawAuthority,
      rawUserInfo,
      rawHost,
      rawAfterAuthority,
      isRawNumeric,
      isHexOrOctalIp,
      leadingWhitespace: /^\s/.test(trimmed),
      hadProtocolRelativeSlash: /^\s*\/\/[^/]/.test(trimmed),
      hadTripleSlashAfterScheme: /^\s*[a-zA-Z][a-zA-Z\d+\-.]*:\/\/\//.test(trimmed),
      mixedCaseScheme: Boolean(rawScheme && rawScheme !== rawScheme.toLowerCase() && rawScheme !== rawScheme.toUpperCase()),
    };
  }

  function classifyIpAddress(hostname, rawAuthorityInfo) {
    const clean = (hostname || '').replace(/^\[|\]$/g, '').toLowerCase();
    const ipv4Match = clean.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    let isIPv4 = false;
    let isPrivateOrLocal = false;

    if (ipv4Match) {
      const octets = ipv4Match.slice(1).map(Number);
      isIPv4 = octets.every((o) => o >= 0 && o <= 255);
      if (isIPv4) {
        const [a, b] = octets;
        isPrivateOrLocal =
          a === 127 ||
          a === 10 ||
          a === 0 ||
          (a === 192 && b === 168) ||
          (a === 172 && b >= 16 && b <= 31) ||
          (a === 169 && b === 254);
      }
    }

    const isIPv6 = clean.includes(':') && /^[0-9a-f:]+$/i.test(clean);
    if (isIPv6 && (clean === '::1' || clean.startsWith('fe80:') || clean.startsWith('fc') || clean.startsWith('fd'))) {
      isPrivateOrLocal = true;
    }

    const isLocalhost = clean === 'localhost' || clean.endsWith('.localhost');
    if (isLocalhost) {
      isPrivateOrLocal = true;
    }

    const hasObfuscatedIp = Boolean(rawAuthorityInfo && (rawAuthorityInfo.isRawNumeric || rawAuthorityInfo.isHexOrOctalIp));
    const hasIpAddress = isIPv4 || isIPv6 || hasObfuscatedIp;

    return {
      hasIpAddress,
      isIPv4,
      isIPv6,
      hasObfuscatedIp,
      isLocalhost,
      isPrivateOrLocal,
      isPublicIp: hasIpAddress && !isPrivateOrLocal,
    };
  }

  function parseDomainParts(hostname, ipInfo) {
    const cleanHost = (hostname || '').toLowerCase().replace(/\.$/, '');
    if (!cleanHost || ipInfo.hasIpAddress || ipInfo.isLocalhost) {
      return {
        hostname: cleanHost,
        tld: '',
        publicSuffix: '',
        sld: cleanHost,
        registrableDomain: cleanHost,
        subdomains: [],
        nonWwwSubdomains: [],
        subdomainStr: '',
        subdomainCount: 0,
        nonWwwSubdomainCount: 0,
        embeddedDomainsInSubdomain: [],
        hasEmbeddedDomainInSubdomain: false,
      };
    }

    const labels = cleanHost.split('.').filter(Boolean);
    if (labels.length < 2) {
      return {
        hostname: cleanHost,
        tld: labels[0] || '',
        publicSuffix: labels[0] || '',
        sld: cleanHost,
        registrableDomain: cleanHost,
        subdomains: [],
        nonWwwSubdomains: [],
        subdomainStr: '',
        subdomainCount: 0,
        nonWwwSubdomainCount: 0,
        embeddedDomainsInSubdomain: [],
        hasEmbeddedDomainInSubdomain: false,
      };
    }

    const lastTwo = labels.slice(-2).join('.');
    const lastThree = labels.length >= 4 ? labels.slice(-3).join('.') : '';
    let suffixLabels = 1;
    if (lastThree && MULTI_PART_SUFFIXES.has(lastThree)) {
      suffixLabels = 3;
    } else if (labels.length >= 3 && MULTI_PART_SUFFIXES.has(lastTwo)) {
      suffixLabels = 2;
    }

    const publicSuffix = labels.slice(-suffixLabels).join('.');
    const tld = labels[labels.length - 1];
    const sldIndex = Math.max(0, labels.length - suffixLabels - 1);
    const sld = labels[sldIndex] || '';
    const registrableDomain = labels.slice(sldIndex).join('.');
    const subdomains = labels.slice(0, sldIndex);

    const nonWwwSubdomains = subdomains.filter((label) => !/^www\d*$/.test(label));
    const subdomainStr = subdomains.join('.');
    const embeddedDomainsInSubdomain = subdomainStr
      ? Array.from(
          new Set(
            (
              subdomainStr.match(
                /\b[a-z0-9-]{2,}\.(?:com|net|org|edu|gov|co|io|uk|de|info|biz|app)(?=\.|$)/gi
              ) || []
            ).map((d) => d.toLowerCase())
          )
        )
      : [];

    return {
      hostname: cleanHost,
      tld,
      publicSuffix,
      sld,
      registrableDomain,
      subdomains,
      nonWwwSubdomains,
      subdomainStr,
      subdomainCount: subdomains.length,
      nonWwwSubdomainCount: nonWwwSubdomains.length,
      embeddedDomainsInSubdomain,
      hasEmbeddedDomainInSubdomain: embeddedDomainsInSubdomain.length > 0,
    };
  }

  function computeShannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = Object.create(null);
    for (let i = 0; i < str.length; i++) {
      freq[str[i]] = (freq[str[i]] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const ch in freq) {
      const p = freq[ch] / len;
      entropy -= p * Math.log2(p);
    }
    return Number(entropy.toFixed(3));
  }

  function countAlnumTransitions(token) {
    const clean = String(token || '').toLowerCase();
    if (!clean) return 0;
    let transitions = 0;
    for (let i = 1; i < clean.length; i++) {
      const prevDigit = clean[i - 1] >= '0' && clean[i - 1] <= '9';
      const curDigit = clean[i] >= '0' && clean[i] <= '9';
      const prevAlpha = clean[i - 1] >= 'a' && clean[i - 1] <= 'z';
      const curAlpha = clean[i] >= 'a' && clean[i] <= 'z';
      if ((prevDigit && curAlpha) || (prevAlpha && curDigit)) {
        transitions += 1;
      }
    }
    return transitions;
  }

  function extractKeywordMatches(domainParts, pathDecoded, queryDecoded) {
    const subTokens = (domainParts.subdomainStr || '').toLowerCase().split(/[.\-_]+/).filter(Boolean);
    const sldTokens = (domainParts.sld || '').toLowerCase().split(/[.\-_]+/).filter(Boolean);
    const nonSuffixHost = [domainParts.subdomainStr, domainParts.sld]
      .filter(Boolean)
      .join('.')
      .toLowerCase();
    const hostTokens = [...subTokens, ...sldTokens];

    const rawPathTokens = (pathDecoded || '').toLowerCase().split(/[^a-z0-9-]+/).filter(Boolean);
    const rawQueryTokens = (queryDecoded || '').toLowerCase().split(/[^a-z0-9-]+/).filter(Boolean);
    const expandHyphenTokens = (list) => {
      const out = [];
      for (const item of list) {
        out.push(item);
        if (item.includes('-')) {
          for (const sub of item.split('-')) {
            if (sub) out.push(sub);
          }
        }
      }
      return out;
    };
    const pathTokens = expandHyphenTokens(rawPathTokens);
    const queryTokens = expandHyphenTokens(rawQueryTokens);
    const pathQueryTokens = [...pathTokens, ...queryTokens];

    // Also inspect obfuscated domain tokens (l0gin, s3cure, ver1fy, acc0unt, passw0rd)
    const obfuscatedDomainLures = [];
    const obfuscationTargets = new Set([
      'login', 'signin', 'verify', 'secure', 'account', 'password',
      'update', 'confirm', 'banking', 'wallet', 'support', 'recovery',
    ]);
    if (BrandDetector && typeof BrandDetector.buildSubstitutionVariants === 'function') {
      for (const tok of hostTokens) {
        if (tok.length < 4 || obfuscationTargets.has(tok)) continue;
        const variants = BrandDetector.buildSubstitutionVariants(tok);
        const match = variants.find((v) => obfuscationTargets.has(v));
        if (match) {
          obfuscatedDomainLures.push({ rawToken: tok, normalizedWord: match });
        }
      }
    }

    const byCategory = {
      credential: [],
      recovery: [],
      urgency: [],
      payment: [],
      securityTrust: [],
    };
    const subdomainHits = [];
    const sldHits = [];
    const pathHits = [];
    const queryHits = [];

    for (const [catName, wordList] of Object.entries(KEYWORD_GROUPS)) {
      for (const kw of wordList) {
        let hitAnywhere = false;
        const pluralTokenRedundant =
          (subTokens.includes(kw + 's') || sldTokens.includes(kw + 's')) &&
          !subTokens.includes(kw) &&
          !sldTokens.includes(kw);
        const subHit =
          subTokens.includes(kw) ||
          (!pluralTokenRedundant && kw.length >= 5 && (domainParts.subdomainStr || '').toLowerCase().includes(kw));
        const sldHit =
          sldTokens.includes(kw) ||
          (!pluralTokenRedundant && kw.length >= 5 && (domainParts.sld || '').toLowerCase().includes(kw));
        const pHit = pathTokens.includes(kw);
        const qHit = kw !== 'https' && kw !== 'ssl' && queryTokens.includes(kw);

        if (subHit) {
          subdomainHits.push(kw);
          hitAnywhere = true;
        }
        if (sldHit) {
          sldHits.push(kw);
          hitAnywhere = true;
        }
        if (pHit && kw !== 'https' && kw !== 'ssl') {
          pathHits.push(kw);
          hitAnywhere = true;
        }
        if (qHit) {
          queryHits.push(kw);
          hitAnywhere = true;
        }
        if (hitAnywhere) {
          byCategory[catName].push(kw);
        }
      }
    }

    const domainCredentialHits = [];
    const domainSecurityHits = [];
    const pathCredentialHits = [];
    const pathSecurityHits = [];

    for (const kw of CREDENTIAL_KEYWORDS) {
      if (hostTokens.includes(kw) || (kw.length >= 5 && nonSuffixHost.includes(kw))) {
        domainCredentialHits.push(kw);
      }
      if (pathQueryTokens.includes(kw)) {
        pathCredentialHits.push(kw);
      }
    }

    for (const kw of SECURITY_TRUST_KEYWORDS) {
      if (hostTokens.includes(kw) || (kw.length >= 5 && nonSuffixHost.includes(kw))) {
        domainSecurityHits.push(kw);
      }
      if (kw !== 'https' && kw !== 'ssl' && pathQueryTokens.includes(kw)) {
        pathSecurityHits.push(kw);
      }
    }

    const uniqueSub = Array.from(new Set(subdomainHits));
    const uniqueSld = Array.from(new Set(sldHits));
    const uniquePath = Array.from(new Set(pathHits));
    const uniqueQuery = Array.from(new Set(queryHits));
    const allDomainHits = Array.from(new Set([...uniqueSub, ...uniqueSld]));
    const allUniqueKeywords = Array.from(new Set([...uniqueSub, ...uniqueSld, ...uniquePath, ...uniqueQuery]));

    return {
      byLocation: {
        subdomain: uniqueSub,
        sld: uniqueSld,
        path: uniquePath,
        query: uniqueQuery,
        domain: allDomainHits,
      },
      byCategory: {
        credential: Array.from(new Set(byCategory.credential)),
        recovery: Array.from(new Set(byCategory.recovery)),
        urgency: Array.from(new Set(byCategory.urgency)),
        payment: Array.from(new Set(byCategory.payment)),
        securityTrust: Array.from(new Set(byCategory.securityTrust)),
      },
      obfuscatedDomainLures,
      domainCredentialHits: Array.from(new Set(domainCredentialHits)),
      domainSecurityHits: Array.from(new Set(domainSecurityHits)),
      pathCredentialHits: Array.from(new Set(pathCredentialHits)),
      pathSecurityHits: Array.from(new Set(pathSecurityHits)),
      allUniqueKeywords,
    };
  }

  function domainIsSameOrSubdomain(hostA, hostB) {
    if (!hostA || !hostB) return false;
    const cleanA = hostA.toLowerCase();
    const cleanB = hostB.toLowerCase();
    return cleanA === cleanB || cleanA.endsWith('.' + cleanB) || cleanB.endsWith('.' + cleanA);
  }

  function extractPathAndQuerySignals(urlObj, domainParts, rawAfterAuthority) {
    const pathname = urlObj.pathname || '/';
    const search = urlObj.search || '';
    const hashRaw = urlObj.hash || '';
    const pathDecoded = safeMultiDecode(pathname, 3);
    const queryDecoded = safeMultiDecode(search, 3);
    const hashDecoded = safeMultiDecode(hashRaw.replace(/^#/, ''), 3);
    const pathSegments = pathDecoded.split('/').filter(Boolean);
    const leafSegment = (pathSegments[pathSegments.length - 1] || '').toLowerCase();

    // File extension checks
    const extParts = leafSegment.split('.');
    const leafExtension = extParts.length >= 2 ? extParts[extParts.length - 1] : '';
    const prevExtension = extParts.length >= 3 ? extParts[extParts.length - 2] : '';
    const hasExecutableExtension = EXECUTABLE_EXTENSIONS.has(leafExtension);
    const hasArchiveExtension = ARCHIVE_EXTENSIONS.has(leafExtension);
    const hasScriptExtension = SCRIPT_EXTENSIONS.has(leafExtension);
    const hasDoubleExtension =
      extParts.length >= 3 &&
      ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'jpg', 'png', 'csv'].includes(prevExtension) &&
      (EXECUTABLE_EXTENSIONS.has(leafExtension) ||
        ARCHIVE_EXTENSIONS.has(leafExtension) ||
        SCRIPT_EXTENSIONS.has(leafExtension) ||
        ['html', 'htm', 'js', 'mjs'].includes(leafExtension));

    const hasMisleadingDocumentName =
      /(invoice|receipt|statement|remittance|wire|tax|shipping|tracking|document|notice|payroll|bill)/i.test(leafSegment) &&
      (['html', 'htm', 'php', 'asp', 'aspx', 'js', 'zip', 'rar'].includes(leafExtension) || hasExecutableExtension || hasDoubleExtension);

    const hasSuspiciousLoginFilename =
      /^(login|signin|sign-in|logon|webscr|auth|authenticate|sso|cmd)\.(php|html?|aspx?|jsp|cgi)$/i.test(leafSegment);
    const hasFakeVerificationFilename =
      /(verify|verification|confirm|confirmation|validate|validation|kyc|unlock|suspend|suspended|security-check).*\.(php|html?|aspx?|jsp|cgi)$/i.test(leafSegment);
    const hasPasswordResetPath =
      /\/(reset[-_]?password|password[-_]?reset|forgot[-_]?password|recover[-_]?account|password\/recover|account\/recover)\b/i.test(pathDecoded);
    const hasPaymentPath =
      /\/(payment|payments|billing|invoice|checkout|wallet|card[-_]?update|credit[-_]?card|verify[-_]?card)\b/i.test(pathDecoded);

    // Long random-looking path segment (ignore hex commit hashes/UUIDs if clean unless high entropy alnum mix)
    const isStandardUuidOrSha = (seg) =>
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg) ||
      /^[0-9a-f]{32}$/i.test(seg) ||
      /^[0-9a-f]{40}$/i.test(seg) ||
      /^[0-9a-f]{64}$/i.test(seg);
    let hasLongRandomPathSegment = false;
    let maxPathSegmentLength = 0;
    for (const seg of pathSegments) {
      if (seg.length > maxPathSegmentLength) maxPathSegmentLength = seg.length;
      if (seg.length >= 28 && !isStandardUuidOrSha(seg)) {
        const stripped = seg.replace(/[^a-z0-9]/gi, '');
        if (stripped.length >= 24 && computeShannonEntropy(stripped.toLowerCase()) >= 3.85 && /[a-z]/i.test(stripped) && /\d/.test(stripped)) {
          hasLongRandomPathSegment = true;
        }
      }
    }

    // Query parameter inspection (parse raw search string to preserve raw encoding evidence)
    const rawPairs = search.replace(/^\?/, '').split('&').filter(Boolean);
    const queryValueLengths = [];
    let maxQueryValueLength = 0;
    let randomLookingQueryCount = 0;
    let encodedQueryParamCount = 0;
    let emailPrefillCount = 0;

    const redirectParams = [];
    const externalUrlParams = [];
    let nestedRedirectCount = 0;
    let encodedExternalRedirectCount = 0;
    let hasSuspiciousExternalRedirectTarget = false;

    for (const pair of rawPairs) {
      const eqIdx = pair.indexOf('=');
      const rawKey = eqIdx >= 0 ? pair.slice(0, eqIdx) : pair;
      const rawVal = eqIdx >= 0 ? pair.slice(eqIdx + 1) : '';
      const keyLower = safeDecode(rawKey).toLowerCase();
      const valOnce = safeDecode(rawVal);
      const valDeep = safeMultiDecode(rawVal, 3);
      const base64Decoded = tryDecodeBase64UrlPrefix(valDeep);
      const inspectedVal = base64Decoded || valDeep;

      queryValueLengths.push(valDeep.length);
      if (valDeep.length > maxQueryValueLength) maxQueryValueLength = valDeep.length;

      if (/%[0-9a-fA-F]{2}|%3D|={1,2}$/i.test(rawVal) && rawVal.length >= 8) {
        encodedQueryParamCount += 1;
      }

      if (valDeep.length >= 28 && /(?=.*[a-z])(?=.*[A-Z0-9])/i.test(valDeep)) {
        const cleanVal = valDeep.replace(/[^a-z0-9]/gi, '');
        if (cleanVal.length >= 24 && computeShannonEntropy(cleanVal.toLowerCase()) >= 3.85) {
          randomLookingQueryCount += 1;
        }
      }

      if ((keyLower === 'email' || keyLower === 'user' || keyLower === 'userid') && /@/.test(valDeep)) {
        emailPrefillCount += 1;
      }

      // Check embedded URLs inside value
      const urlMatches = inspectedVal.match(/(?:https?:\/\/|\/\/)[^\s"'<>]+/gi) || [];
      const hasEmbeddedUrl = urlMatches.length > 0;
      const isRedirectKey = REDIRECT_PARAM_NAMES.has(keyLower);

      if (hasEmbeddedUrl && (isRedirectKey || keyLower !== 'q')) {
        externalUrlParams.push({ key: keyLower, targets: urlMatches });
      }

      if (isRedirectKey) {
        const isUrlTarget = hasEmbeddedUrl || /^(?:https?%3a|\/\/|%2f%2f)/i.test(rawVal) || Boolean(base64Decoded);
        if (isUrlTarget) {
          let targetHost = '';
          let isSameSite = false;
          for (const targetRaw of urlMatches) {
            const parsedTarget = normalizeUrl(targetRaw);
            if (parsedTarget) {
              targetHost = parsedTarget.hostname.toLowerCase();
              if (targetHost === domainParts.hostname || targetHost.endsWith('.' + domainParts.registrableDomain) || domainIsSameOrSubdomain(domainParts.hostname, targetHost)) {
                isSameSite = true;
              }
              // Nested redirect check: does target URL ITSELF carry a redirect param or second http(s)://?
              const targetSearch = parsedTarget.search || '';
              let targetHasRedirect = false;
              parsedTarget.searchParams.forEach((_, k) => {
                if (REDIRECT_PARAM_NAMES.has(k.toLowerCase())) targetHasRedirect = true;
              });
              if (targetHasRedirect || /(?:https?:\/\/|https?%3a)/i.test(targetSearch)) {
                nestedRedirectCount += 1;
              }
              const chainHosts = new Set([targetHost]);
              const embeddedHostRegex = /(?:https?:\/\/|\/\/)([a-zA-Z0-9.\-:\[\]]+)/g;
              let hm;
              while ((hm = embeddedHostRegex.exec(inspectedVal)) !== null) {
                chainHosts.add(hm[1].toLowerCase().replace(/:\d+$/, ''));
              }
              for (const chainHost of chainHosts) {
                if (!chainHost || chainHost === domainParts.hostname || domainIsSameOrSubdomain(domainParts.hostname, chainHost)) {
                  continue;
                }
                const targetIpInfo = classifyIpAddress(chainHost);
                const targetParts = parseDomainParts(chainHost, targetIpInfo);
                if (
                  HIGH_RISK_TLDS.has(targetParts.tld) ||
                  targetIpInfo.isPublicIp ||
                  targetIpInfo.hasObfuscatedIp ||
                  targetParts.hasEmbeddedDomainInSubdomain ||
                  (MODERATE_RISK_TLDS.has(targetParts.tld) &&
                    /(login|signin|verify|auth|password|account|confirm|billing)/i.test(targetRaw)) ||
                  /(login|signin|verify|auth|password|account|confirm|billing)/i.test(targetRaw) && HIGH_RISK_TLDS.has(targetParts.tld)
                ) {
                  hasSuspiciousExternalRedirectTarget = true;
                }
              }
            }
          }

          if (urlMatches.length >= 2) {
            nestedRedirectCount += 1;
          }
          const isOpenRedirectPath = pathSegments.some((seg) =>
            OPEN_REDIRECT_PATH_SEGMENTS.has(seg.toLowerCase())
          );
          const wasObfuscatedRedirect =
            Boolean(base64Decoded) ||
            /%25(?:3a|2f)|%2e/i.test(rawVal) ||
            (/https?%3a|%2f%2f/i.test(rawVal) &&
              (isOpenRedirectPath || hasSuspiciousExternalRedirectTarget || nestedRedirectCount > 0));
          if (wasObfuscatedRedirect && !isSameSite) {
            encodedExternalRedirectCount += 1;
          }

          redirectParams.push({
            key: keyLower,
            targetHost,
            isSameSite,
            isSameBrandSibling: false,
            isExternalUnrelated: Boolean(targetHost && !isSameSite),
            wasEncoded: wasObfuscatedRedirect,
          });
        }
      }
    }

    // Inspect URL fragment (#hash) for hidden victim email prefills, Base64 URLs, or embedded external destinations
    let fragmentRedirectOrEmailDetected = false;
    if (hashDecoded) {
      if (/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i.test(hashDecoded)) {
        emailPrefillCount += 1;
        fragmentRedirectOrEmailDetected = true;
      }
      const hashTokens = hashDecoded.split(/[&#=?/\s]+/).filter(Boolean);
      const decodedHashTargets = [];
      for (const ht of hashTokens) {
        const b64 = tryDecodeBase64UrlPrefix(ht);
        if (b64) {
          decodedHashTargets.push(b64);
          fragmentRedirectOrEmailDetected = true;
          encodedExternalRedirectCount += 1;
        }
      }
      const directHashUrls = hashDecoded.match(/(?:https?:\/\/|\/\/)[^\s"'<>]+/gi) || [];
      for (const u of directHashUrls) {
        decodedHashTargets.push(u);
      }
      if (decodedHashTargets.length > 0) {
        fragmentRedirectOrEmailDetected = true;
        externalUrlParams.push({ key: '#fragment', targets: decodedHashTargets });
        for (const targetRaw of decodedHashTargets) {
          const parsedTarget = normalizeUrl(targetRaw);
          if (!parsedTarget) continue;
          const tHost = parsedTarget.hostname.toLowerCase();
          if (tHost && tHost !== domainParts.hostname && !domainIsSameOrSubdomain(domainParts.hostname, tHost)) {
            const targetIpInfo = classifyIpAddress(tHost);
            const targetParts = parseDomainParts(tHost, targetIpInfo);
            if (
              HIGH_RISK_TLDS.has(targetParts.tld) ||
              targetIpInfo.isPublicIp ||
              targetIpInfo.hasObfuscatedIp ||
              targetParts.hasEmbeddedDomainInSubdomain
            ) {
              hasSuspiciousExternalRedirectTarget = true;
            }
          }
        }
      }
    }

    const externalRedirectParams = redirectParams.filter((r) => r.isExternalUnrelated);
    const hasOpenRedirectPath = pathSegments.some((seg) =>
      OPEN_REDIRECT_PATH_SEGMENTS.has(seg.toLowerCase())
    );
    const isOpenRedirectStructure = hasOpenRedirectPath && externalRedirectParams.length > 0;

    // Embedded domain-like strings inside path, query, or fragment that differ from actual domain
    // Strip email address parameters so user emails (e.g. email=user@gmail.com or user%40gmail.com) are not treated as deceptive embedded domains.
    const queryAndHashWithoutEmails = (queryDecoded + ' ' + hashDecoded)
      .replace(/(?:^|[?&#=])(?:email|login_hint|username|user|mail|account)=[^&#\s]+/gi, '')
      .replace(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi, '');

    const embeddedDomainMatches =
      (pathDecoded + ' ' + queryAndHashWithoutEmails).match(
        /\b[a-z0-9-]{2,}\.(?:com|net|org|co|io|uk|de|info|biz|tk|ml|ga|cf|gq|top|xyz|app|cfd|sbs)\b/gi
      ) || [];
    const unrelatedEmbeddedDomains = Array.from(
      new Set(
        embeddedDomainMatches
          .map((d) => d.toLowerCase())
          .filter((d) => d !== domainParts.registrableDomain && d !== domainParts.hostname)
      )
    );

    const hasProtocolInPath = /(?:https?:\/\/|https?:%2f%2f)/i.test(pathname);
    const hasDoubleSlashAfterHost = /\/\//.test(rawAfterAuthority.split(/[?#]/)[0] || '');

    return {
      pathDecoded,
      queryDecoded,
      hashDecoded,
      fragmentRedirectOrEmailDetected,
      pathLength: pathDecoded.length,
      pathSegments,
      pathSegmentCount: pathSegments.length,
      maxPathSegmentLength,
      leafSegment,
      leafExtension,
      hasExecutableExtension,
      hasArchiveExtension,
      hasScriptExtension,
      hasDoubleExtension,
      hasMisleadingDocumentName,
      hasSuspiciousLoginFilename,
      hasFakeVerificationFilename,
      hasPasswordResetPath,
      hasPaymentPath,
      hasLongRandomPathSegment,
      queryLength: search.length,
      queryParamCount: rawPairs.length,
      maxQueryValueLength,
      randomLookingQueryCount,
      encodedQueryParamCount,
      emailPrefillCount,
      redirectParams,
      externalRedirectParams,
      externalUrlParams,
      nestedRedirectCount,
      encodedExternalRedirectCount,
      hasSuspiciousExternalRedirectTarget,
      isOpenRedirectStructure,
      unrelatedEmbeddedDomains,
      hasProtocolInPath,
      hasDoubleSlashAfterHost,
      hasExtensionWithSuspiciousQuery:
        Boolean(leafExtension) &&
        (hasScriptExtension || leafExtension === 'html' || leafExtension === 'htm') &&
        (emailPrefillCount > 0 || externalRedirectParams.length > 0 || /cmd=|session=|token=/i.test(search)),
    };
  }

  function extractFeatures(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') {
      return {
        valid: false,
        supported: false,
        rawUrl: String(rawUrl || ''),
        error: 'Empty or invalid URL input',
      };
    }

    const exemptInfo = classifyExemptUrl(rawUrl);
    if (exemptInfo.isExempt) {
      return {
        valid: false,
        supported: false,
        exempt: true,
        isInternalBrowserPage: true,
        isPdfViewer: exemptInfo.isPdfViewer,
        isLocalFile: exemptInfo.isLocalFile,
        exemptCategory: exemptInfo.category,
        exemptScheme: exemptInfo.scheme,
        rawUrl: String(rawUrl || ''),
        error: exemptInfo.reason,
      };
    }

    const supportedCheck = isSupportedUrl(rawUrl);
    const urlObj = normalizeUrl(rawUrl);

    if (!urlObj) {
      return {
        valid: false,
        supported: false,
        rawUrl,
        error: 'Malformed URL',
      };
    }

    const rawAuthorityInfo = parseRawSlices(rawUrl);
    const normalizedUrl = urlObj.href;
    const protocol = urlObj.protocol.toLowerCase();
    const isHttps = protocol === 'https:';
    const isHttp = protocol === 'http:';
    const hostname = urlObj.hostname.toLowerCase();
    const port = urlObj.port || '';
    const hasNonStandardPort =
      Boolean(port) && !((isHttp && port === '80') || (isHttps && port === '443'));

    const hasUserInfo = Boolean(urlObj.username || urlObj.password);
    const userinfoStr = [urlObj.username, urlObj.password].filter(Boolean).join(':');
    const atCount = (rawUrl.match(/@/g) || []).length;
    const hasMultipleAt = atCount >= 2;
    const hasAtSymbol = atCount > 0;
    const hasAtInAuthority =
      hasUserInfo ||
      (rawAuthorityInfo.rawAuthority || '').includes('@') ||
      /%40/i.test(rawAuthorityInfo.rawAuthority || '');

    const ipInfo = classifyIpAddress(hostname, rawAuthorityInfo);
    const domainParts = parseDomainParts(hostname, ipInfo);

    // Strip 'xn--' Punycode prefix before computing structural label metrics
    const hostLabels = hostname.split('.');
    const nonPunycodeLabels = hostLabels.map((label) =>
      label.startsWith('xn--') ? label.slice(4) : label
    );
    const nonPunycodeHost = nonPunycodeLabels.join('.');
    const nonPunycodeSld = domainParts.sld.startsWith('xn--')
      ? domainParts.sld.slice(4)
      : domainParts.sld;

    // Length & Complexity Counts
    const urlLength = normalizedUrl.length;
    const domainLength = hostname.length;
    const subdomainStrLength = domainParts.subdomainStr.length;
    const maxSubdomainLabelLength = domainParts.subdomains.reduce((m, l) => Math.max(m, l.length), 0);
    const maxDomainLabelLength = nonPunycodeLabels.reduce((m, l) => Math.max(m, l.length), 0);

    const dotCountInHost = (hostname.match(/\./g) || []).length;
    const dotCountTotal = (normalizedUrl.match(/\./g) || []).length;
    const hyphenCountInHost = (nonPunycodeHost.match(/-/g) || []).length;
    const hyphenCountInSld = (nonPunycodeSld.match(/-/g) || []).length;
    const hyphenCountTotal = (normalizedUrl.match(/-/g) || []).length;
    const underscoreCountInHost = (hostname.match(/_/g) || []).length;
    const underscoreCountTotal = (normalizedUrl.match(/_/g) || []).length;
    const digitCountUrl = (normalizedUrl.match(/\d/g) || []).length;
    const digitsInHost = (nonPunycodeHost.match(/\d/g) || []).length;
    const digitsInSld = (nonPunycodeSld.match(/\d/g) || []).length;
    const digitRatioInSld = nonPunycodeSld.length ? digitsInSld / nonPunycodeSld.length : 0;

    const specialCharMatches = normalizedUrl.match(SPECIAL_CHAR_REGEX) || [];
    const specialCharCount = specialCharMatches.length;
    const specialCharRatio = urlLength > 0 ? Number((specialCharCount / urlLength).toFixed(3)) : 0;
    const nonSchemeUrl = normalizedUrl.replace(/^https?:\/\//i, '');
    const punctuationCount = (nonSchemeUrl.match(PUNCTUATION_REGEX) || []).length;
    const punctuationDensity = nonSchemeUrl.length > 0
      ? Number((punctuationCount / nonSchemeUrl.length).toFixed(3))
      : 0;

    const fragmentMatches = rawUrl.match(/#/g) || [];
    const fragmentCount = fragmentMatches.length;
    const fragmentLength = (urlObj.hash || '').length;

    const alnumTransitionsHost = nonPunycodeLabels
      .filter((l) => !ipInfo.hasIpAddress)
      .reduce((sum, lbl) => sum + countAlnumTransitions(lbl), 0);

    // Consecutive separators & repeated character patterns
    const hasConsecutiveHyphensInHost = nonPunycodeLabels.some((label) => label.includes('--'));
    const hasConsecutiveUnderscores = normalizedUrl.includes('__');
    const hasDoubleDots = rawAuthorityInfo.rawHost.includes('..') || (urlObj.pathname || '').includes('..');
    const hasConsecutiveSeparators =
      hasConsecutiveHyphensInHost || hasConsecutiveUnderscores || hasDoubleDots;

    const hostRepeatedChar = /(.)\1{3,}/i.test(nonPunycodeHost);
    const pathRepeatedChar = /(.)\1{4,}|([a-z]{2,3})\2{2,}/i.test(urlObj.pathname || '');
    const hasRepeatedSpecialChars = /([!?&_~*$=-])\1{2,}|\?\?|\&\&|==/i.test(rawAfterSchemeSafe(rawUrl));

    const sldEntropy = computeShannonEntropy(nonPunycodeSld);
    const vowelCountSld = (nonPunycodeSld.match(/[aeiouy]/gi) || []).length;
    const alphaCountSld = (nonPunycodeSld.match(/[a-z]/gi) || []).length;
    const sldVowelRatio = alphaCountSld > 0 ? Number((vowelCountSld / alphaCountSld).toFixed(3)) : 1;
    const sldHyphenWordList = nonPunycodeSld.split('-').filter(Boolean);
    const hasRandomSubToken = sldHyphenWordList.some((tok) => {
      if (tok.length < 10) return false;
      const tokAlnum = tok.replace(/[^a-z0-9]/gi, '');
      const tokVowels = (tok.match(/[aeiouy]/gi) || []).length;
      const tokAlpha = (tok.match(/[a-z]/gi) || []).length;
      const tokVowelRatio = tokAlpha > 0 ? tokVowels / tokAlpha : 1;
      return computeShannonEntropy(tokAlnum.toLowerCase()) >= 3.7 || (tokAlpha >= 10 && tokVowelRatio < 0.16);
    });
    const isReadableMultiWordSld =
      sldHyphenWordList.length >= 2 && sldVowelRatio >= 0.22 && !hasRandomSubToken;
    const hasHighDomainEntropy =
      !ipInfo.hasIpAddress &&
      nonPunycodeSld.length >= 12 &&
      !isReadableMultiWordSld &&
      sldEntropy >= 3.6;
    const hasRandomLookingDomain =
      !ipInfo.hasIpAddress &&
      nonPunycodeSld.length >= 10 &&
      !isReadableMultiWordSld &&
      (sldEntropy >= 3.65 || (alphaCountSld >= 10 && sldVowelRatio < 0.16) || hasRandomSubToken);

    // Encoding, Unicode, Bidi & Character Manipulation
    const rawHostHasNonAscii = /[^\x00-\x7f]/.test(rawAuthorityInfo.rawHost || '');
    const hasPunycode = hostLabels.some((label) => label.startsWith('xn--'));
    const percentEncodedMatches = rawUrl.match(/%[0-9a-fA-F]{2}/g) || [];
    const nonSpaceEncodedMatches = percentEncodedMatches.filter((m) => m.toUpperCase() !== '%20');
    const hasDoubleEncoding = /%25(?:[0-9a-fA-F]{2}|%[0-9a-fA-F]{2})/i.test(rawUrl);
    const rawBeforeQuery = rawAfterSchemeSafe(rawUrl).split('?')[0] || '';
    const hasEncodedDot = /%2e/i.test(rawUrl);
    const hasEncodedSlash = /%2f/i.test(rawUrl);
    const hasEncodedDotOrSlashInPath = /%2e|%2f/i.test(rawBeforeQuery) || hasEncodedDot || /%25(?:2e|2f)/i.test(rawUrl);
    const hasEncodedBackslash = /%5c/i.test(rawUrl);
    // Encoded "@" (%40) is an authority manipulation attack when placed in authority/userinfo (e.g. legit%40evil.com).
    // In query strings or paths (e.g. email=user%40example.com), %40 is standard percent-encoding of email addresses.
    const hasEncodedAt = /%40/i.test(rawAuthorityInfo.rawAuthority || '');
    const hasHexEscapeInAuthority = /%[0-9a-fA-F]{2}/.test(rawAuthorityInfo.rawHost || '');
    const hasExcessivePercentEncoding = nonSpaceEncodedMatches.length >= 6 || hasDoubleEncoding;
    const hasHexSequences =
      /0x[0-9a-f]{4,}/i.test(rawUrl) ||
      hasHexEscapeInAuthority ||
      /\/[0-9a-f]{24,}(?:\/|$)/i.test(urlObj.pathname || '');

    const decodedHostForScript = BrandDetector
      ? BrandDetector.decodePunycodeDomain(hostname)
      : hostname;
    const hasBidiChars =
      BIDI_CHAR_REGEX.test(rawUrl) ||
      BIDI_CHAR_REGEX.test(decodedHostForScript) ||
      /%E2%80%A[A-E]|%E2%81%A[6-9]|%E2%80%[89][E-F]/i.test(rawUrl);
    const hasInvisibleUnicode =
      INVISIBLE_UNICODE_REGEX.test(rawUrl) ||
      INVISIBLE_UNICODE_REGEX.test(decodedHostForScript) ||
      /%E2%80%8[B-D]|%EF%BB%BF|%C2%AD/i.test(rawUrl);
    const hasTilde = rawUrl.includes('~');
    const hasBackslash = rawUrl.includes('\\') || hasEncodedBackslash;
    const hasBackslashInAuthority = /[\\]|%5c/i.test(rawAuthorityInfo.rawAuthority || '');

    // Domain Prefix/Suffix, Repeated Labels, Unusual Formatting
    const sldHyphenTokens = nonPunycodeSld.split('-').filter(Boolean);
    const subHyphenTokens = domainParts.subdomainStr.split(/[.\-]/).filter(Boolean);
    const allHostWords = [...subHyphenTokens, ...sldHyphenTokens];

    const suspiciousDomainPrefixes = [];
    const suspiciousDomainSuffixes = [];
    for (const label of [nonPunycodeSld, ...domainParts.nonWwwSubdomains]) {
      const parts = label.split('-').filter(Boolean);
      if (parts.length >= 2) {
        if (HOST_AFFIX_WORDS.includes(parts[0])) {
          suspiciousDomainPrefixes.push(`${parts[0]}-`);
        }
        const last = parts[parts.length - 1];
        if (HOST_AFFIX_WORDS.includes(last)) {
          suspiciousDomainSuffixes.push(`-${last}`);
        }
      }
    }

    const labelFreq = Object.create(null);
    const repeatedDomainLabels = [];
    for (const lbl of domainParts.nonWwwSubdomains) {
      labelFreq[lbl] = (labelFreq[lbl] || 0) + 1;
      if (labelFreq[lbl] === 2) repeatedDomainLabels.push(lbl);
    }
    if (domainParts.nonWwwSubdomains.includes(domainParts.sld) && domainParts.sld.length >= 4) {
      repeatedDomainLabels.push(domainParts.sld);
    }

    const hasNumericTld = /^\d+$/.test(domainParts.tld);
    const hasEmptyLabelDots = /\.\./.test(rawAuthorityInfo.rawHost || '');
    const hasLeadingOrTrailingHyphen = hostLabels.some((l) => l.startsWith('-') || l.endsWith('-'));
    const hasUnderscoreInHost = underscoreCountInHost > 0;

    // TLD
    const tld = domainParts.tld;
    const isHighRiskTld = HIGH_RISK_TLDS.has(tld);
    const isModerateRiskTld = MODERATE_RISK_TLDS.has(tld);
    const hasDomainShapedUserinfo = Boolean(
      hasUserInfo && /[a-z0-9-]{2,}\.[a-z]{2,}/i.test(userinfoStr)
    );

    const pathDecoded = safeMultiDecode(urlObj.pathname || '/', 3);
    const queryDecoded = safeMultiDecode(urlObj.search || '', 3);
    const keywords = extractKeywordMatches(domainParts, pathDecoded, queryDecoded);

    const hostLookalike = BrandDetector
      ? BrandDetector.analyzeHostLookalikes({
          domainParts,
          rawHost: rawAuthorityInfo.rawHost,
        })
      : {
          decodedHost: hostname,
          scriptInfo: { hasMixedScriptsInLabel: false, hasMixedScriptsAcrossHost: false, scripts: [] },
          hasConfusableCharsInHost: false,
          medialDigitSubstitutions: { detected: false, matches: [] },
          boundaryDigitSubstitutions: { detected: false, matches: [] },
          hasMedialDigitSubstitution: false,
          hasBoundaryDigitSubstitution: false,
          hasLookalikeDigitSubstitution: false,
        };

    const pathAndQuery = extractPathAndQuerySignals(
      urlObj,
      domainParts,
      rawAuthorityInfo.rawAfterAuthority
    );

    // Protocol anomalies in raw URL (ignore single standard redirect/callback parameter without suspicious target)
    const protocolMatches = (rawUrl.match(/https?(?::\/\/|%3a%2f%2f)/gi) || []).length;
    const benignSingleRedirectCallback =
      protocolMatches === 2 &&
      pathAndQuery.redirectParams.length === 1 &&
      !pathAndQuery.hasProtocolInPath &&
      !pathAndQuery.fragmentRedirectOrEmailDetected &&
      !pathAndQuery.nestedRedirectCount &&
      !pathAndQuery.hasSuspiciousExternalRedirectTarget &&
      !hasDoubleEncoding;
    const hasMultipleProtocolStrings = protocolMatches >= 2 && !benignSingleRedirectCallback;
    const hasHttpsKeywordInDomain =
      domainParts.subdomainStr.includes('https') ||
      domainParts.sld.includes('https') ||
      domainParts.subdomainStr.includes('http-') ||
      domainParts.sld.includes('http-') ||
      domainParts.subdomainStr.includes('ssl-') ||
      domainParts.sld.includes('ssl-');

    const hasExcessiveSubdomains =
      !ipInfo.hasIpAddress && domainParts.nonWwwSubdomainCount >= 3;
    const hasExcessiveHyphens = hyphenCountInHost >= 3 || hyphenCountTotal >= 7;
    const isUnusuallyLongUrl = urlLength > 100;
    const isVeryLongUrl = urlLength > 160;
    const hasLongDomain = domainLength > 35;

    const hasNumericHeavyDomain = !ipInfo.hasIpAddress && nonPunycodeSld.length >= 6 && digitRatioInSld >= 0.45;
    const hasSuspiciousDomainStructure =
      hasConsecutiveHyphensInHost ||
      hasNumericHeavyDomain ||
      hasHighDomainEntropy ||
      hasHttpsKeywordInDomain ||
      Boolean(domainParts.hasEmbeddedDomainInSubdomain) ||
      hyphenCountInHost >= 4;

    const hasMisleadingDomain =
      Boolean(domainParts.hasEmbeddedDomainInSubdomain) ||
      Boolean(hostLookalike.hasLookalikeDigitSubstitution) ||
      hasDomainShapedUserinfo ||
      hasAtInAuthority ||
      hasPunycode ||
      rawHostHasNonAscii ||
      (hostLookalike.scriptInfo && hostLookalike.scriptInfo.hasMixedScriptsInLabel);

    return {
      valid: true,
      supported: supportedCheck,
      rawUrl,
      normalizedUrl,
      protocol,
      isHttps,
      isHttp,
      hostname,
      port,
      hasNonStandardPort,
      rawAuthorityInfo,
      domainParts,
      ipInfo,

      // 1. URL Structure & Complexity (Category A)
      structure: {
        urlLength,
        domainLength,
        subdomainStrLength,
        maxSubdomainLabelLength,
        maxDomainLabelLength,
        pathLength: pathAndQuery.pathLength,
        pathSegmentCount: pathAndQuery.pathSegmentCount,
        maxPathSegmentLength: pathAndQuery.maxPathSegmentLength,
        queryLength: pathAndQuery.queryLength,
        queryParamCount: pathAndQuery.queryParamCount,
        maxQueryValueLength: pathAndQuery.maxQueryValueLength,
        fragmentCount,
        fragmentLength,
        subdomainCount: domainParts.subdomainCount,
        nonWwwSubdomainCount: domainParts.nonWwwSubdomainCount,
        dotCountInHost,
        dotCountTotal,
        hyphenCountInHost,
        hyphenCountInSld,
        hyphenCountTotal,
        underscoreCountInHost,
        underscoreCountTotal,
        digitCountUrl,
        digitsInHost,
        digitsInSld,
        digitRatioInSld,
        alnumTransitionsHost,
        specialCharCount,
        specialCharRatio,
        punctuationCount,
        punctuationDensity,
        hasConsecutiveSeparators,
        hostRepeatedChar,
        pathRepeatedChar,
        hasRepeatedSpecialChars,
        hasIpAddress: ipInfo.hasIpAddress,
        isIPv4: ipInfo.isIPv4,
        isIPv6: ipInfo.isIPv6,
        isPublicIp: ipInfo.isPublicIp,
        isPrivateOrLocalIp: ipInfo.isPrivateOrLocal,
        hasObfuscatedIp: ipInfo.hasObfuscatedIp,
        isLocalhost: ipInfo.isLocalhost,
      },

      // 2. Domain Characteristics (Categories C, D, I)
      domain: {
        registrableDomain: domainParts.registrableDomain,
        sld: domainParts.sld,
        sldWordCount: sldHyphenTokens.length,
        allHostWordCount: allHostWords.length,
        tld,
        publicSuffix: domainParts.publicSuffix,
        decodedHost: hostLookalike.decodedHost,
        hasSuspiciousDomainStructure,
        hasExcessiveSubdomains,
        isHighRiskTld,
        isModerateRiskTld,
        hasSuspiciousTld: isHighRiskTld || isModerateRiskTld,
        hasMisleadingDomain,
        hasPunycode,
        rawHostHasNonAscii,
        scriptInfo: hostLookalike.scriptInfo,
        hasConfusableCharsInHost: hostLookalike.hasConfusableCharsInHost,
        sldEntropy,
        sldVowelRatio,
        hasHighDomainEntropy,
        hasRandomLookingDomain,
        hasNumericHeavyDomain,
        hasConsecutiveHyphensInHost,
        hasLongDomain,
        suspiciousDomainPrefixes: Array.from(new Set(suspiciousDomainPrefixes)),
        suspiciousDomainSuffixes: Array.from(new Set(suspiciousDomainSuffixes)),
        repeatedDomainLabels: Array.from(new Set(repeatedDomainLabels)),
        hasNumericTld,
        hasEmptyLabelDots,
        hasLeadingOrTrailingHyphen,
        hasUnderscoreInHost,
        embeddedDomainsInSubdomain: domainParts.embeddedDomainsInSubdomain || [],
        hasEmbeddedDomainInSubdomain: Boolean(domainParts.hasEmbeddedDomainInSubdomain),
        medialDigitSubstitutions: hostLookalike.medialDigitSubstitutions || { detected: false, matches: [] },
        boundaryDigitSubstitutions: hostLookalike.boundaryDigitSubstitutions || { detected: false, matches: [] },
        hasMedialDigitSubstitution: Boolean(hostLookalike.hasMedialDigitSubstitution),
        hasBoundaryDigitSubstitution: Boolean(hostLookalike.hasBoundaryDigitSubstitution),
        hasLookalikeDigitSubstitution: Boolean(hostLookalike.hasLookalikeDigitSubstitution),
        unrelatedEmbeddedDomains: pathAndQuery.unrelatedEmbeddedDomains,
      },

      // 3. Suspicious Characters, Paths, Redirects & Protocols (Categories B, E, F, G, H)
      patterns: {
        atCount,
        hasAtSymbol,
        hasMultipleAt,
        hasAtInAuthority,
        hasDomainShapedUserinfo,
        hasExcessiveHyphens,
        percentEncodedCount: percentEncodedMatches.length,
        nonSpaceEncodedCount: nonSpaceEncodedMatches.length,
        hasDoubleEncoding,
        hasEncodedDot,
        hasEncodedSlash,
        hasEncodedDotOrSlashInPath,
        hasEncodedBackslash,
        hasEncodedAt,
        hasHexEscapeInAuthority,
        hasHexSequences,
        hasHexOrEncodedChars:
          percentEncodedMatches.length > 0 ||
          ipInfo.hasObfuscatedIp ||
          hasDoubleEncoding,
        hasExcessivePercentEncoding,
        hasBidiChars,
        hasInvisibleUnicode,
        hasTilde,
        hasBackslash,
        hasBackslashInAuthority,
        hasHttpsKeywordInDomain,
        hasProtocolInPath: pathAndQuery.hasProtocolInPath,
        hasMultipleProtocolStrings,
        hasDoubleSlashAfterHost: pathAndQuery.hasDoubleSlashAfterHost,
        unusualProtocolFormatting:
          rawAuthorityInfo.leadingWhitespace ||
          rawAuthorityInfo.hadProtocolRelativeSlash ||
          rawAuthorityInfo.hadTripleSlashAfterScheme ||
          rawAuthorityInfo.mixedCaseScheme,
        keywords,
        pathAndQuery,
        isUnusuallyLongUrl,
        isVeryLongUrl,
      },
    };
  }

  function rawAfterSchemeSafe(rawUrl) {
    return String(rawUrl || '').replace(/^\s*https?:\/\//i, '');
  }

  return {
    isSupportedUrl,
    classifyExemptUrl,
    CHROME_PDF_VIEWER_EXTENSION_ID,
    normalizeUrl,
    extractFeatures,
    HIGH_RISK_TLDS,
    MODERATE_RISK_TLDS,
    KEYWORD_GROUPS,
  };
});
