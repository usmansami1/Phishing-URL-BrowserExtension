/**
 * PhishGuard - Purely Rule-Based Detection & Scoring Test Suite
 * Tests structural, character, keyword, host, protocol, redirect, and combination
 * rules with ZERO stored URL lists, brand databases, or whitelists/blacklists.
 * Run with: node --test Phishing-URL-BrowserExtension/tests/detection.test.js
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const BrandDetector = require(path.join(__dirname, '..', 'src', 'brandDetector.js'));
const URLAnalyzer = require(path.join(__dirname, '..', 'src', 'urlAnalyzer.js'));
const RuleEngine = require(path.join(__dirname, '..', 'src', 'ruleEngine.js'));
const RiskScorer = require(path.join(__dirname, '..', 'src', 'riskScorer.js'));
const Detector = require(path.join(__dirname, '..', 'src', 'detector.js'));

function assertRuleMetadataComplete(res, contextLabel) {
  assert.ok(Array.isArray(res.rules), `${contextLabel}: missing res.rules array`);
  assert.ok(res.ruleSummary && typeof res.ruleSummary.totalTriggered === 'number');
  for (const r of res.rules) {
    assert.ok(typeof r.ruleId === 'string' && r.ruleId.length > 0, `${contextLabel}: empty ruleId`);
    assert.ok(typeof r.ruleName === 'string' && r.ruleName.length > 0, `${contextLabel}: empty ruleName`);
    assert.ok(typeof r.category === 'string' && r.category.length > 0, `${contextLabel}: empty category`);
    assert.ok(['low', 'medium', 'high'].includes(r.severity), `${contextLabel}: bad severity ${r.severity}`);
    assert.ok(['weak', 'medium', 'strong'].includes(r.indicatorStrength), `${contextLabel}: bad strength ${r.indicatorStrength}`);
    assert.ok(typeof r.explanation === 'string' && r.explanation.length > 10, `${contextLabel}: missing explanation for ${r.ruleId}`);
    assert.ok(typeof r.evidence === 'string' && r.evidence.length > 5, `${contextLabel}: missing evidence for ${r.ruleId}`);
  }
}

test('No stored brand database, shortener list, threat feed lookup, or domain whitelist/blacklist exists', () => {
  assert.equal(BrandDetector.BRAND_CATALOG, undefined);
  assert.equal(URLAnalyzer.BRAND_CATALOG, undefined);
  assert.equal(URLAnalyzer.URL_SHORTENERS, undefined);
  assert.equal(Detector.registerThreatIntelProvider, undefined);
  assert.equal(Detector.analyzeUrlWithIntel, undefined);

  // Clean well-known AND unfamiliar domains have 0 meaningful phishing indicators => SAFE (never UNVERIFIED merely for being unfamiliar)
  for (const cleanUrl of [
    'https://google.com/',
    'https://www.google.com/',
    'https://myaccount.google.com/',
    'https://myaccount.google.com/security',
    'https://myaccount.google.com/signinoptions/password',
    'https://myaccount.google.com/account-recovery?email=user%40gmail.com&continue=https%3A%2F%2Fmyaccount.google.com%2Fsecurity',
    'https://accounts.google.com/',
    'https://accounts.google.com/ServiceLogin?service=accountsettings&continue=https%3A%2F%2Fmyaccount.google.com%2F',
    'https://paypal.com/',
    'https://microsoft.com/',
    'https://example.com/',
    'https://en.wikipedia.org/wiki/Phishing',
    'https://unknownsite.example/',
    'https://unknown-local-bakery.org/menu',
    'https://unfamiliar-small-business-store.com/products/coffee-beans?page=2&sort=price',
  ]) {
    const res = Detector.analyzeUrl(cleanUrl);
    assert.equal(res.classification, 'SAFE', `Expected SAFE on ${cleanUrl}, got ${res.classification} (${res.riskScore})`);
    assert.equal(res.riskLevel, 'Safe');
    assert.equal(res.riskBadge, 'SAFE');
    assert.equal(res.uiState, 'safe');
    assert.equal(res.assessmentType, 'rule_based');
    assert.equal(res.impersonatedBrand, null);
    assert.equal(res.shouldBlock, false);
  }
});

test('URLs with harmless multi-digit numbers, short tech tags, single hyphens, or minor weak signals classify as SAFE', () => {
  const ordinaryUrls = [
    'https://node2.com/',
    'https://shop24.com/',
    'https://web3.dev/',
    'https://my-blog.example.com/',
    'https://pay-pal.com/',
    'https://ample.com/',
    'https://stream.com/',
    'https://check-ups.org/',
    'https://my-company-blog-2026.co.uk/posts/welcome',
    'https://my-university-portal-info.edu/students/schedule',
    'https://app.example.com/oauth/authorize?redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback',
    'https://us-east-1.console.example.com/login',
    'https://github.com/login',
    'https://upstream.dev/login',
    'http://localhost:3000/login',
    'https://example.com/articles/' + 'a'.repeat(140),
  ];

  for (const url of ordinaryUrls) {
    const res = Detector.analyzeUrl(url);
    assertRuleMetadataComplete(res, url);
    assert.equal(res.classification, 'SAFE', `False warning on ${url}: ${res.classification} (${res.riskScore}) [${res.rules.map((r) => r.ruleId).join(', ')}]`);
    assert.equal(res.uiState, 'safe');
    assert.equal(res.shouldBlock, false);
  }

  // Plain HTTP surfaces the Not Secure note without falsely declaring phishing
  const httpRes = Detector.analyzeUrl('http://example.com/');
  assert.equal(httpRes.classification, 'SAFE');
  assert.equal(httpRes.riskLevel, 'Safe');
  assert.equal(httpRes.shouldBlock, false);
  assert.ok(httpRes.checks.some((c) => c.name === 'Unencrypted HTTP connection' && c.status === 'Not Secure'));
});

test('Character/digit substitution detects g00gle.com, amaz0n.com, qa1am.com, and paypa1.com as SUSPICIOUS and escalates to PHISHING with lure context', () => {
  for (const url of ['https://qa1am.com/', 'https://g00gle.com/', 'https://amaz0n.com/']) {
    const res = Detector.analyzeUrl(url);
    assertRuleMetadataComplete(res, url);
    assert.equal(res.classification, 'SUSPICIOUS', `Expected SUSPICIOUS on bare ${url}, got ${res.classification}`);
    assert.equal(res.uiState, 'phishing');
    assert.equal(res.shouldBlock, true);
    assert.ok(res.rules.some((r) => r.ruleId === 'medial_digit_substitution'));
    assert.ok(res.rules.some((r) => r.ruleId === 'alphanumeric_mix_host'));
  }

  for (const url of ['paypa1.com', 'https://paypa1.com/', 'https://wellsfarg0.com/', 'https://0utlook.com/']) {
    const res = Detector.analyzeUrl(url);
    assertRuleMetadataComplete(res, url);
    assert.equal(res.classification, 'SUSPICIOUS', `Expected SUSPICIOUS on bare ${url}, got ${res.classification}`);
    assert.equal(res.uiState, 'phishing');
    assert.equal(res.shouldBlock, true);
    assert.ok(res.rules.some((r) => r.ruleId === 'boundary_digit_substitution'));
  }

  // Short technical abbreviations and multi-digit suffixes must not trigger digit substitution
  for (const tech of ['https://a11y.dev/', 'https://i18n.example.org/', 'https://w3c.org/', 'https://b2b.example.com/', 'https://html5.org/', 'https://base64.org/']) {
    const res = Detector.analyzeUrl(tech);
    assert.equal(res.classification, 'SAFE');
    assert.equal(res.rules.some((r) => r.ruleId === 'medial_digit_substitution' || r.ruleId === 'boundary_digit_substitution'), false, `False digit-sub trigger on ${tech}`);
  }

  // Pairing character substitution with credential/lure/HTTP/TLD cues escalates to PHISHING
  for (const phishingUrl of [
    'http://qa1am.tk/login',
    'https://qa1am.com/verify-account/login.php',
    'https://g00gle.com/login',
    'https://amaz0n.com/signin',
    'https://paypa1.com/login',
    'http://g00gle.tk/verify',
    'http://paypa1.tk/verify-account/login.php',
  ]) {
    const res = Detector.analyzeUrl(phishingUrl);
    assertRuleMetadataComplete(res, phishingUrl);
    assert.equal(res.classification, 'PHISHING', `Expected PHISHING for ${phishingUrl}, got ${res.classification} (${res.riskScore})`);
    assert.equal(res.riskLevel, 'High Risk');
    assert.equal(res.shouldBlock, true);
  }
});

test('Mixed-script Unicode and Punycode homographs trigger PHISHING while valid single-script IDNs remain SAFE', () => {
  for (const badIdn of [
    'https://p\u0430ypal.com/',
    'https://p\u0430ypal.com/login',
    'https://xn--microsft-sbh.com/login',
    'https://xn--pypal-4ve.com/login',
  ]) {
    const res = Detector.analyzeUrl(badIdn);
    assertRuleMetadataComplete(res, badIdn);
    assert.equal(res.classification, 'PHISHING', `Missed IDN homograph ${badIdn}: ${res.classification} (${res.riskScore})`);
    assert.equal(res.shouldBlock, true);
    assert.ok(res.rules.some((r) => r.ruleId === 'mixed_scripts_in_domain'));
    assert.ok(res.rules.some((r) => r.ruleId === 'idn_homoglyph_mimicry'));
    assert.ok(res.rules.some((r) => r.ruleId === 'combo_punycode_plus_lure'));
  }

  // Valid German Punycode IDN (bücher.de) uses pure Latin script and stays SAFE
  const validIdn = Detector.analyzeUrl('https://xn--bcher-kva.de/');
  assert.equal(validIdn.classification, 'SAFE');
  assert.equal(validIdn.uiState, 'safe');
  assert.equal(validIdn.shouldBlock, false);
});

test('Embedded domain-in-subdomain mimicry and deep subdomain lures escalate from SUSPICIOUS to PHISHING', () => {
  const bareEmbed = Detector.analyzeUrl('https://microsoftonline.com.attacker.com/');
  assertRuleMetadataComplete(bareEmbed, 'bareEmbed');
  assert.equal(bareEmbed.classification, 'SUSPICIOUS');
  assert.equal(bareEmbed.uiState, 'phishing');
  assert.ok(bareEmbed.rules.some((r) => r.ruleId === 'embedded_domain_in_subdomain'));

  for (const highSub of [
    'https://login.microsoftonline.com.evil.com/',
    'https://accounts.google.com.evil.com/',
    'https://paypal.com.example.org/verify',
    'https://login.verify.client-portal.com/signin',
    'https://secure.account.verify.update.billing.example-portal.top/signin',
  ]) {
    const res = Detector.analyzeUrl(highSub);
    assertRuleMetadataComplete(res, highSub);
    assert.equal(res.classification, 'PHISHING', `Expected PHISHING for ${highSub}, got ${res.classification} (${res.riskScore})`);
    assert.equal(res.shouldBlock, true);
  }
});

test('IP-based, authority-deceptive, double-encoded, and open-redirect URLs vs failed UNVERIFIED inputs', () => {
  const barePublicIp = Detector.analyzeUrl('http://45.33.32.156/');
  assert.equal(barePublicIp.classification, 'SUSPICIOUS');
  assert.equal(barePublicIp.shouldBlock, true);

  for (const url of [
    'http://45.33.32.156/verify-account',
    'http://198.51.100.42/verify-account/login.php?session=a1b2c3d4',
    'http://[2001:db8::1]/account/login/verify',
    'http://3325256746/verify-login.php',
    'https://user@example.com@evil-verify.tk/signin',
    'https://login.example.com@evil-login.tk/verify',
    'https://verify-account.example.org/%70%61%79/%2e%2e%25%32%46login.php?u=aHR0cHM6Ly9leGFtcGxlLm9yZw==',
    'https://example.org/redirect?next=https://evil-verify.tk/go?target=https%3A%2F%2Fexample.net%2Flogin',
    'https://example.org/go?url=https%3A%2F%2Fevil-verify.tk%2Flogin',
    'http://https-login.example.org:8443/http://target/signin',
  ]) {
    const res = Detector.analyzeUrl(url);
    assertRuleMetadataComplete(res, url);
    assert.equal(res.classification, 'PHISHING', `Expected PHISHING on ${url}, got ${res.classification} (${res.riskScore})`);
    assert.equal(res.shouldBlock, true);
  }

  // Unsupported, malformed, or missing inputs resolve to UNVERIFIED with clear verification-failure messaging
  for (const unverifiedInput of ['', null, undefined, 'javascript:alert(1)', 'not a valid ::: url']) {
    const res = Detector.analyzeUrl(unverifiedInput);
    assert.equal(res.classification, 'UNVERIFIED');
    assert.equal(res.riskBadge, 'UNVERIFIED');
    assert.equal(res.statusTitle, 'Unable to Verify URL');
    assert.equal(res.uiState, 'phishing');
    assert.equal(res.shouldBlock, true);
  }

  for (const exemptUrl of [
    'chrome://extensions',
    'edge://settings/privacy',
    'about:blank',
    'chrome-extension://mhjfbmdgcfjbbpaeojofohoefgiehjai/index.html',
    'chrome-extension://mhjfbmdgcfjbbpaeojofohoefgiehjai/content/web/viewer.html?file=file%3A%2F%2F%2FC%3A%2Freport.pdf',
    'file:///C:/Users/hp/Documents/statement.pdf',
  ]) {
    const exemptRes = Detector.analyzeUrl(exemptUrl);
    assert.equal(exemptRes.classification, 'EXEMPT', `Expected EXEMPT for ${exemptUrl}`);
    assert.notEqual(exemptRes.classification, 'SAFE');
    assert.notEqual(exemptRes.classification, 'PHISHING');
    assert.equal(exemptRes.exempt, true);
    assert.equal(exemptRes.isInternalBrowserPage, true);
    assert.equal(exemptRes.supported, false);
    assert.equal(exemptRes.shouldBlock, false);
    assert.equal(exemptRes.uiState, 'neutral');
    assert.equal(exemptRes.rules.length, 0);
  }
});

test('Optional registration-age context integrates with rule engine without external lists or feeds', () => {
  const freshPhish = Detector.analyzeUrl('https://fresh-lure.example/login/password/verify', {
    registrationInfo: { domainAgeDays: 4 },
  });
  assert.equal(freshPhish.assessmentType, 'rule_based');
  assert.equal(freshPhish.classification, 'PHISHING');
  assert.ok(freshPhish.rules.some((r) => r.ruleId === 'very_recent_domain'));
  assert.ok(freshPhish.rules.some((r) => r.ruleId === 'combo_keywords_plus_new_domain'));
});

test('Weight keys between RuleEngine and RiskScorer match 1:1 with zero dead/missing weights', () => {
  const fs = require('node:fs');
  const ruleSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'ruleEngine.js'), 'utf8');
  const engineKeys = new Set();
  for (const m of ruleSrc.matchAll(/(?:\bw|c\.w)\.([A-Za-z0-9_]+)/g)) {
    engineKeys.add(m[1]);
  }
  const scorerKeys = new Set(Object.keys(RiskScorer.DEFAULT_CONFIG.weights));
  assert.deepEqual([...engineKeys].filter((k) => !scorerKeys.has(k)), []);
  assert.deepEqual([...scorerKeys].filter((k) => !engineKeys.has(k)), []);
  assert.equal(BrandDetector.decodePunycodeDomain('xn--bcher-kva.de'), 'bücher.de');
});
