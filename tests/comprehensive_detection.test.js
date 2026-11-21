/**
 * PhishGuard - Comprehensive Purely Rule-Based & End-to-End Detection Suite
 * Run with: node --test Phishing-URL-BrowserExtension/tests/*.js
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const EXT_ROOT = path.join(__dirname, '..');
const BrandDetector = require(path.join(EXT_ROOT, 'src', 'brandDetector.js'));
const URLAnalyzer = require(path.join(EXT_ROOT, 'src', 'urlAnalyzer.js'));
const RuleEngine = require(path.join(EXT_ROOT, 'src', 'ruleEngine.js'));
const RiskScorer = require(path.join(EXT_ROOT, 'src', 'riskScorer.js'));
const Detector = require(path.join(EXT_ROOT, 'src', 'detector.js'));

const MULTI_CATEGORY_CASES = [
  // 1. Legitimate & unfamiliar ordinary websites => SAFE (never UNVERIFIED or blocked merely for weak signals / unfamiliarity)
  { category: '1. Legit / Unfamiliar', url: 'https://google.com/', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://www.google.com/', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://myaccount.google.com/', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://myaccount.google.com/security', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://myaccount.google.com/signinoptions/password', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://accounts.google.com/', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://paypal.com/', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://example.com/', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://en.wikipedia.org/wiki/Phishing', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://web.mit.edu/', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://node2.com/', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://shop24.com/', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://web3.dev/', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://my-blog.example.com/', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'http://example.com/', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://github.com/login', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://us-east-1.console.example.com/login', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://my-blog.example.com/articles/top-10-security-tips', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://unknown-local-bakery.org/menu', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://unfamiliar-small-business-store.com/products/coffee-beans?page=2&sort=price', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://my-university-portal-info.edu/students/schedule', expected: ['SAFE'] },
  { category: '1. Legit / Unfamiliar', url: 'https://app.example.com/oauth/authorize?redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback', expected: ['SAFE'] },

  // 2. Character/digit substitution test cases (brand-free generic rules)
  { category: '2. Digit Substitution', url: 'https://qa1am.com/', expected: ['SUSPICIOUS'] },
  { category: '2. Digit Substitution', url: 'https://g00gle.com/', expected: ['SUSPICIOUS'] },
  { category: '2. Digit Substitution', url: 'https://amaz0n.com/', expected: ['SUSPICIOUS'] },
  { category: '2. Digit Substitution', url: 'https://paypa1.com/', expected: ['SUSPICIOUS'] },
  { category: '2. Digit Substitution', url: 'http://qa1am.tk/login', expected: ['PHISHING'] },
  { category: '2. Digit Substitution', url: 'https://g00gle.com/login', expected: ['PHISHING'] },
  { category: '2. Digit Substitution', url: 'https://amaz0n.com/signin', expected: ['PHISHING'] },
  { category: '2. Digit Substitution', url: 'https://paypa1.com/login', expected: ['PHISHING'] },
  { category: '2. Digit Substitution', url: 'http://g00gle.tk/verify', expected: ['PHISHING'] },
  { category: '2. Digit Substitution', url: 'http://paypa1.tk/verify-account/login.php', expected: ['PHISHING'] },
  { category: '2. Digit Substitution', url: 'https://m1crosoft-login.com/verify', expected: ['PHISHING'] },

  // 3. Suspicious IP-based URLs
  { category: '3. Suspicious IP URLs', url: 'http://45.33.32.156/', expected: ['SUSPICIOUS'] },
  { category: '3. Suspicious IP URLs', url: 'http://45.33.32.156/verify-account', expected: ['PHISHING'] },
  { category: '3. Suspicious IP URLs', url: 'http://198.51.100.42/verify-account/login.php?session=a1b2c3d4', expected: ['PHISHING'] },
  { category: '3. Suspicious IP URLs', url: 'http://[2001:db8::1]/account/login/verify', expected: ['PHISHING'] },
  { category: '3. Suspicious IP URLs', url: 'http://3325256746/verify-login.php', expected: ['PHISHING'] },
  { category: '3. Suspicious IP URLs', url: 'http://0306.063.0144.052/login', expected: ['PHISHING'] },
  { category: '3. Suspicious IP URLs', url: 'http://0xc6.0x33.0x64.0x2a/signin', expected: ['PHISHING'] },

  // 4. Punycode / Unicode mixed-script homographs (+ valid IDN control)
  { category: '4. Punycode & Homoglyphs', url: 'https://p\u0430ypal.com/', expected: ['PHISHING'] },
  { category: '4. Punycode & Homoglyphs', url: 'https://p\u0430ypal.com/login', expected: ['PHISHING'] },
  { category: '4. Punycode & Homoglyphs', url: 'https://xn--microsft-sbh.com/login', expected: ['PHISHING'] },
  { category: '4. Punycode & Homoglyphs', url: 'https://xn--pypal-4ve.com/login', expected: ['PHISHING'] },
  { category: '4. Punycode & Homoglyphs', url: 'https://g\u043e\u043egle.com/', expected: ['PHISHING'] },
  { category: '4. Punycode & Homoglyphs', url: 'https://pay\u200Bpal-verify.example.org/', expected: ['SUSPICIOUS', 'PHISHING'] },
  { category: '4. Punycode & Homoglyphs', url: 'https://example.org/file_\u202Ecod.pdf', expected: ['SUSPICIOUS', 'PHISHING'] },
  { category: '4. Punycode & Homoglyphs', url: 'https://xn--bcher-kva.de/', expected: ['SAFE'] },

  // 5. Suspicious Subdomain Structures
  { category: '5. Subdomain Structures', url: 'https://microsoftonline.com.attacker.com/', expected: ['SUSPICIOUS'] },
  { category: '5. Subdomain Structures', url: 'https://login.microsoftonline.com.evil.com/', expected: ['PHISHING'] },
  { category: '5. Subdomain Structures', url: 'https://accounts.google.com.evil.com/', expected: ['PHISHING'] },
  { category: '5. Subdomain Structures', url: 'https://paypal.com.example.org/verify', expected: ['PHISHING'] },
  { category: '5. Subdomain Structures', url: 'https://mail.login.verify.account.evil.org/', expected: ['PHISHING'] },
  { category: '5. Subdomain Structures', url: 'https://login.verify.client-portal.com/signin', expected: ['PHISHING'] },
  { category: '5. Subdomain Structures', url: 'https://secure.account.verify.update.billing.example-portal.top/signin', expected: ['PHISHING'] },

  // 6. Encoded / Authority Obfuscated / Redirect URLs
  { category: '6. Encoded & Redirects', url: 'https://login.example.com@evil-login.tk/verify', expected: ['PHISHING'] },
  { category: '6. Encoded & Redirects', url: 'https://example.org\\@evil.com/login', expected: ['PHISHING'] },
  { category: '6. Encoded & Redirects', url: 'https://example.org%40evil.com/login', expected: ['PHISHING'] },
  { category: '6. Encoded & Redirects', url: 'https://verify-account.example.org/%70%61%79/%2e%2e%25%32%46login.php?u=aHR0cHM6Ly9leGFtcGxlLm9yZw==', expected: ['PHISHING'] },
  { category: '6. Encoded & Redirects', url: 'https://example.org/redirect?next=https://evil-verify.tk/go?target=https%3A%2F%2Fexample.net%2Flogin', expected: ['PHISHING'] },
  { category: '6. Encoded & Redirects', url: 'https://example.org/go?url=https%3A%2F%2Fevil-verify.tk%2Flogin', expected: ['PHISHING'] },
  { category: '6. Encoded & Redirects', url: 'https://login-check.example.top/#aHR0cHM6Ly9leGFtcGxlLm9yZw==', expected: ['PHISHING'] },

  // 7. Generic multi-signal phishing URLs & Verification failure cases
  { category: '7. Generic Multi-Signal', url: 'http://account-update-portal.xyz/login', expected: ['PHISHING'] },
  { category: '7. Generic Multi-Signal', url: 'https://client-auth-portal.tk/login?email=victim@corp.com', expected: ['PHISHING'] },
  { category: '7. Generic Multi-Signal', url: 'https://portal-check.xyz/login#victim@corp.com', expected: ['PHISHING'] },
  { category: '7. Generic Multi-Signal', url: 'https://xk8p9q2m7z4r1w6n3v.top/account/verify/password/reset/k9x2m7p4q1z8r3w6v5n2c9', expected: ['PHISHING'] },
  { category: '7. Generic Multi-Signal', url: 'https://billing-notice.example.org/invoice_042.pdf.exe', expected: ['SUSPICIOUS', 'PHISHING'] },
  { category: '7. Generic Multi-Signal', url: 'http://https-login.example.org:8443/http://target/signin', expected: ['PHISHING'] },
  { category: '8. Failure / Unverified', url: 'not a valid ::: url', expected: ['UNVERIFIED'] },
  { category: '8. Failure / Unverified', url: '', expected: ['UNVERIFIED'] },
];

test('Central Rule Execution Pipeline registers and executes all stages into RiskScorer and Detector', () => {
  const registeredStages = RuleEngine.getRegisteredPipelineStages();
  assert.ok(Array.isArray(registeredStages) && registeredStages.length === 11);

  const testUrl = 'https://g00gle-verify.com/login?next=https%3A%2F%2Fevil.tk';
  const features = URLAnalyzer.extractFeatures(testUrl);
  const evaluated = RuleEngine.evaluateRules(features, {});
  assert.equal(evaluated.pipelineStagesExecuted.length, registeredStages.length);
  for (const st of registeredStages) {
    assert.ok(evaluated.pipelineStagesExecuted.includes(st.stageId), `Missing stage execution: ${st.stageId}`);
  }

  for (const rule of evaluated.rules) {
    assert.ok(rule.ruleId && rule.ruleName && rule.category);
    assert.ok(typeof rule.explanation === 'string' && rule.explanation.length > 10);
    assert.ok(typeof rule.evidence === 'string' && rule.evidence.length > 5);
    assert.equal(typeof rule.weight, 'number');
  }

  const scored = RiskScorer.scoreFeatures(features);
  assert.deepEqual(
    scored.rules.map((r) => r.ruleId).sort(),
    evaluated.rules.map((r) => r.ruleId).sort()
  );
  assert.deepEqual(scored.ruleSummary.pipelineStagesExecuted, evaluated.pipelineStagesExecuted);

  const detected = Detector.analyzeUrl(testUrl);
  assert.equal(detected.riskLevel, 'High Risk');
  assert.equal(detected.riskScore, scored.score);
  assert.deepEqual(
    detected.rules.map((r) => r.ruleId),
    scored.rules.map((r) => r.ruleId)
  );
});

test('Comprehensive rule-based URL matrix passes with detailed reporting', () => {
  const rows = [];
  const failures = [];

  for (const tc of MULTI_CATEGORY_CASES) {
    const res = Detector.analyzeUrl(tc.url);
    const passed = tc.expected.includes(res.classification);
    const ruleIds = (res.rules || []).map((r) => r.ruleId);
    rows.push({
      category: tc.category,
      inputUrl: tc.url,
      expected: tc.expected.join(' or '),
      actual: `${res.classification} (${res.riskScore})`,
      triggeredRules: ruleIds.join(', ') || '(none)',
      passed,
    });
    if (!passed) {
      failures.push(`${tc.category} | ${tc.url} -> expected [${tc.expected.join('/')}], got ${res.classification} (${res.riskScore}) [${ruleIds.join(', ')}]`);
    }
  }

  console.log(`\n[PhishGuard Rule Matrix] Verified ${rows.length} URL cases across 7 generic categories:`);
  for (const r of rows) {
    const shortUrl = r.inputUrl.length > 54 ? r.inputUrl.slice(0, 51) + '...' : r.inputUrl;
    console.log(
      `  ${r.passed ? 'PASS' : 'FAIL'} | ${r.category.padEnd(23)} | ${shortUrl.padEnd(54)} | Exp: ${r.expected.padEnd(21)} | Act: ${r.actual.padEnd(18)} | Rules: ${r.triggeredRules}`
    );
  }

  assert.equal(failures.length, 0, `Detection matrix failures:\n${failures.join('\n')}`);
});

test('Background service worker preserves raw URL evidence, syncs verdicts cleanly, and guarantees parity', async () => {
  const listeners = {
    beforeNavigate: [],
    committed: [],
    onUpdated: [],
    onActivated: [],
    onMessage: [],
    onRemoved: [],
  };
  const sessionStore = {};
  const tabRecords = new Map([
    [101, { id: 101, windowId: 1, url: 'about:blank' }],
    [102, { id: 102, windowId: 1, url: 'about:blank' }],
  ]);
  const updatedTabs = [];
  const actionUpdates = [];

  const mockChrome = {
    runtime: {
      lastError: null,
      getURL: (rel) => `chrome-extension://test-ext-id/${rel}`,
      onInstalled: { addListener: () => {} },
      onStartup: { addListener: () => {} },
      onMessage: { addListener: (fn) => listeners.onMessage.push(fn) },
      onMessageExternal: { addListener: () => {} },
    },
    storage: {
      session: {
        get: async (k) => ({ [k]: sessionStore[k] }),
        set: async (obj) => Object.assign(sessionStore, obj),
      },
    },
    webNavigation: {
      onBeforeNavigate: { addListener: (fn) => listeners.beforeNavigate.push(fn) },
      onCommitted: { addListener: (fn) => listeners.committed.push(fn) },
      onHistoryStateUpdated: { addListener: () => {} },
      onReferenceFragmentUpdated: { addListener: () => {} },
    },
    tabs: {
      query: async () => [],
      get: async (id) => tabRecords.get(id) || null,
      update: async (id, patch) => {
        updatedTabs.push({ id, patch });
        const cur = tabRecords.get(id) || { id };
        tabRecords.set(id, { ...cur, ...patch });
        return tabRecords.get(id);
      },
      create: async (patch) => patch,
      onUpdated: { addListener: (fn) => listeners.onUpdated.push(fn) },
      onActivated: { addListener: (fn) => listeners.onActivated.push(fn) },
      onRemoved: { addListener: (fn) => listeners.onRemoved.push(fn) },
    },
    windows: { update: async () => {} },
    action: {
      setPopup: async (info) => actionUpdates.push({ type: 'setPopup', ...info }),
      setIcon: async (info) => actionUpdates.push({ type: 'setIcon', ...info }),
      setTitle: async (info) => actionUpdates.push({ type: 'setTitle', ...info }),
      setBadgeText: async (info) => actionUpdates.push({ type: 'setBadgeText', ...info }),
      setBadgeBackgroundColor: async (info) => actionUpdates.push({ type: 'setBadgeColor', ...info }),
      onClicked: { addListener: () => {} },
    },
  };

  const sandbox = {
    console, Date, Math, Set, Map, Array, Object, String, Number, Boolean, RegExp, Error, Promise, JSON,
    URL, URLSearchParams, atob, btoa, encodeURIComponent, decodeURIComponent, setTimeout, clearTimeout,
    chrome: mockChrome,
    importScripts: (...relPaths) => {
      for (const rel of relPaths) {
        const cleanRel = rel.replace(/^\.\//, '');
        const code = fs.readFileSync(path.join(EXT_ROOT, cleanRel), 'utf8');
        vm.runInContext(code, sandbox, { filename: cleanRel });
      }
    },
  };
  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;
  vm.createContext(sandbox);

  const bgCode = fs.readFileSync(path.join(EXT_ROOT, 'background.js'), 'utf8');
  vm.runInContext(bgCode, sandbox, { filename: 'background.js' });

  const sendMessageToBg = (msg) =>
    new Promise((resolve) => {
      listeners.onMessage[0](msg, {}, (resp) => resolve(resp));
    });

  // 1. Verify Manual Scan preserves raw URL obfuscations
  const rawScanUrls = [
    'qa1am.com',
    'paypa1.com',
    'g00gle.com',
    'https://login.example.com%40evil.tk/verify',
    'https://example.org\\@evil.com/login',
    'http://0306.063.0144.052/login',
    'https://verify-account.example.org/%70%61%79/%2e%2e%25%32%46login.php?u=aHR0cHM6Ly9leGFtcGxlLm9yZw==',
  ];

  for (const rawInput of rawScanUrls) {
    const manualResp = await sendMessageToBg({ type: 'PHISHGUARD_MANUAL_SCAN', url: rawInput });
    const directRes = Detector.analyzeUrl(rawInput);
    assert.equal(manualResp.ok, true);
    assert.equal(manualResp.result.riskLevel, directRes.riskLevel, `Manual scan mismatch for ${rawInput}`);
    assert.equal(manualResp.result.riskScore, directRes.riskScore, `Manual scan score mismatch for ${rawInput}`);
    assert.deepEqual(
      Array.from(manualResp.result.rules.map((r) => r.ruleId)),
      Array.from(directRes.rules.map((r) => r.ruleId))
    );
  }

  // Verify scanner.js validateUserUrlInput preserves rawUrl without stripping obfuscations
  const domMock = {
    location: { search: '' },
    addEventListener: () => {},
    getElementById: () => null,
    querySelectorAll: () => [],
  };
  const winMock = {
    location: domMock.location,
    PhishGuardBrandDetector: BrandDetector,
    PhishGuardURLAnalyzer: URLAnalyzer,
    PhishGuardRuleEngine: RuleEngine,
    PhishGuardRiskScorer: RiskScorer,
    PhishGuardDetector: Detector,
  };
  const scannerSandbox = {
    window: winMock, document: domMock, URL, URLSearchParams, setTimeout, clearTimeout, console,
  };
  winMock.window = winMock;
  vm.createContext(scannerSandbox);
  const scannerCode = fs.readFileSync(path.join(EXT_ROOT, 'src', 'scanner.js'), 'utf8');
  vm.runInContext(scannerCode, scannerSandbox, { filename: 'src/scanner.js' });
  const scannerApi = winMock.PhishGuardScanner;
  assert.ok(scannerApi && typeof scannerApi.validateUserUrlInput === 'function');

  for (const trickyInput of [
    'https://example.org\\@evil.com/login',
    'https://login.example.com%40evil.tk/verify',
    'http://0306.063.0144.052/login',
    'https://verify-account.example.org/%2e%2e/login',
    'qa1am.com',
  ]) {
    const v = scannerApi.validateUserUrlInput(trickyInput);
    assert.equal(v.valid, true, `Expected valid scanner input for ${trickyInput}`);
    assert.equal(v.rawUrl, trickyInput, `Scanner stripped raw evidence from ${trickyInput}`);
  }

  // Verify independent per-tab monitoring: SAFE allows normal browsing, non-SAFE opens warning
  await listeners.beforeNavigate[0]({ tabId: 101, frameId: 0, url: 'https://example.com/' });
  await listeners.beforeNavigate[0]({ tabId: 102, frameId: 0, url: 'https://g00gle.com/login' });
  await new Promise((r) => setTimeout(r, 80));

  const tab1Status = await sendMessageToBg({ type: 'PHISHGUARD_GET_TAB_STATUS', tabId: 101, url: 'https://example.com/' });
  const tab2Status = await sendMessageToBg({ type: 'PHISHGUARD_GET_TAB_STATUS', tabId: 102, url: 'https://g00gle.com/login' });

  assert.equal(tab1Status.result.classification, 'SAFE');
  assert.equal(tab1Status.result.riskLevel, 'Safe');
  assert.equal(tab2Status.result.classification, 'PHISHING');
  assert.equal(tab2Status.result.riskLevel, 'High Risk');
  assert.equal(
    updatedTabs.some(
      (u) => u.id === 101 && u.patch.url && u.patch.url.startsWith('chrome-extension://test-ext-id/index.html?mode=warning')
    ),
    false,
    'Ordinary SAFE site https://example.com/ must NOT be redirected to warning'
  );
  assert.ok(
    updatedTabs.some(
      (u) => u.id === 102 && u.patch.url && u.patch.url.startsWith('chrome-extension://test-ext-id/index.html?mode=warning')
    )
  );

  // 2. Cross-method parity (Manual Scanner vs Automatic Navigation across SAFE, SUSPICIOUS, PHISHING, UNVERIFIED)
  const parityCases = [
    { label: 'Legit HTTPS (SAFE)', url: 'https://example.com/', expectOutcome: 'SAFE', expectWarning: false },
    { label: 'Legit HTTP (SAFE)', url: 'http://example.com/', expectOutcome: 'SAFE', expectWarning: false },
    { label: 'Legit Login Path (SAFE)', url: 'https://github.com/login', expectOutcome: 'SAFE', expectWarning: false },
    { label: 'Unfamiliar Hyphen (SAFE)', url: 'https://unknown-local-bakery.org/menu', expectOutcome: 'SAFE', expectWarning: false },
    { label: 'Unfamiliar Store (SAFE)', url: 'https://unfamiliar-small-business-store.com/products/coffee-beans?page=2&sort=price', expectOutcome: 'SAFE', expectWarning: false },
    { label: 'qa1am.com (SUSPICIOUS)', url: 'https://qa1am.com/', expectOutcome: 'SUSPICIOUS', expectWarning: true },
    { label: 'g00gle.com (SUSPICIOUS)', url: 'https://g00gle.com/', expectOutcome: 'SUSPICIOUS', expectWarning: true },
    { label: 'amaz0n.com (SUSPICIOUS)', url: 'https://amaz0n.com/', expectOutcome: 'SUSPICIOUS', expectWarning: true },
    { label: 'paypa1.com (SUSPICIOUS)', url: 'https://paypa1.com/', expectOutcome: 'SUSPICIOUS', expectWarning: true },
    { label: 'Bare Public IP (SUSPICIOUS)', url: 'http://45.33.32.156/', expectOutcome: 'SUSPICIOUS', expectWarning: true },
    { label: 'paypa1.com + /login', url: 'https://paypa1.com/login', expectOutcome: 'PHISHING', expectWarning: true },
    { label: 'paypa1.tk + phishing path', url: 'http://paypa1.tk/verify-account/login.php', expectOutcome: 'PHISHING', expectWarning: true },
    { label: 'IP + credential workflow', url: 'http://45.33.32.156/verify-account', expectOutcome: 'PHISHING', expectWarning: true },
    { label: 'Punycode + mixed script', url: 'https://xn--microsft-sbh.com/login', expectOutcome: 'PHISHING', expectWarning: true },
    { label: 'Encoded redirect parameter', url: 'https://example.org/go?url=https%3A%2F%2Fevil-verify.tk%2Flogin', expectOutcome: 'PHISHING', expectWarning: true },
    { label: 'Embedded domain subdomain', url: 'https://login.microsoftonline.com.evil.com/', expectOutcome: 'PHISHING', expectWarning: true },
    { label: 'Multiple suspicious subs', url: 'https://login.verify.account.security.example-portal.top/signin', expectOutcome: 'PHISHING', expectWarning: true },
    { label: 'Keywords + obfuscation', url: 'https://verify-account.example.org/%70%61%79/%2e%2e%25%32%46login.php?u=aHR0cHM6Ly9leGFtcGxlLm9yZw==', expectOutcome: 'PHISHING', expectWarning: true },
  ];

  console.log('\n[PhishGuard Parity] Automatic Navigation vs Manual URL Scanner:');
  for (let i = 0; i < parityCases.length; i++) {
    const pc = parityCases[i];
    const testTabId = 200 + i;
    tabRecords.set(testTabId, { id: testTabId, windowId: 1, url: 'about:blank' });

    const manualResp = await sendMessageToBg({ type: 'PHISHGUARD_MANUAL_SCAN', url: pc.url });
    assert.equal(manualResp.ok, true);

    const beforeUpdates = updatedTabs.length;
    await listeners.beforeNavigate[0]({ tabId: testTabId, frameId: 0, url: pc.url });
    // Duplicate commit / updated events for the same navigation must not open duplicate warning tabs
    await listeners.committed[0]({ tabId: testTabId, frameId: 0, url: pc.url, transitionType: 'link' });
    await new Promise((r) => setTimeout(r, 60));
    const navStatus = await sendMessageToBg({
      type: 'PHISHGUARD_GET_TAB_STATUS',
      tabId: testTabId,
      url: pc.url,
    });
    const warningRedirectsForNav = updatedTabs
      .slice(beforeUpdates)
      .filter((u) => u.id === testTabId && u.patch.url && u.patch.url.startsWith('chrome-extension://test-ext-id/index.html?mode=warning'));
    const warningActivated = warningRedirectsForNav.length > 0;

    assert.equal(manualResp.result.classification, pc.expectOutcome);
    assert.equal(navStatus.result.classification, manualResp.result.classification);
    assert.equal(navStatus.result.riskLevel, manualResp.result.riskLevel);
    assert.equal(navStatus.result.riskScore, manualResp.result.riskScore);
    assert.deepEqual(
      Array.from(navStatus.result.rules.map((r) => r.ruleId)),
      Array.from(manualResp.result.rules.map((r) => r.ruleId))
    );
    assert.equal(warningActivated, pc.expectWarning, `Expected warning=${pc.expectWarning} for ${pc.url}`);
    assert.equal(
      warningRedirectsForNav.length,
      pc.expectWarning ? 1 : 0,
      `Expected ${pc.expectWarning ? 1 : 0} warning redirect(s) for ${pc.url}`
    );

    const evidenceStr = (manualResp.result.rules || []).slice(0, 2).map((r) => r.evidence).join(' | ') || 'None';
    console.log(
      `  PASS | ${pc.label.padEnd(28)} | host=${manualResp.result.hostname.padEnd(30)} | cls=${manualResp.result.classification.padEnd(10)} (${String(manualResp.result.riskScore).padStart(3)}) | warning=${String(warningActivated).padEnd(5)} | rules=${manualResp.result.rules.map((r) => r.ruleId).join(', ') || '(none)'} | ev=${evidenceStr}`
    );
  }

  // 3. Verify automatic warning activation across the 4 internal outcomes (+ error/invalid fallbacks):
  // SAFE bypasses warning; SUSPICIOUS, PHISHING, and UNVERIFIED (or invalid/throw) open warning.
  const classificationMatrix = [
    { name: 'SAFE outcome', mockResult: { outcome: 'SAFE', classification: 'SAFE', riskLevel: 'Safe', url: 'https://safe.example/' }, expectOpen: false },
    { name: 'SUSPICIOUS outcome', mockResult: { outcome: 'SUSPICIOUS', classification: 'SUSPICIOUS', riskLevel: 'Suspicious', url: 'https://s.example/' }, expectOpen: true },
    { name: 'PHISHING outcome', mockResult: { outcome: 'PHISHING', classification: 'PHISHING', riskLevel: 'High Risk', url: 'https://p.example/' }, expectOpen: true },
    { name: 'UNVERIFIED outcome', mockResult: { outcome: 'UNVERIFIED', classification: 'UNVERIFIED', riskLevel: 'Unverified', url: 'https://u.example/' }, expectOpen: true },
    { name: 'null result', mockResult: null, expectOpen: true },
    { name: 'undefined result', mockResult: undefined, expectOpen: true },
    { name: 'empty classification', mockResult: { riskLevel: '', classification: '', url: 'https://empty.example/' }, expectOpen: true },
    { name: 'invalid object classification', mockResult: { riskLevel: null, classification: 123, url: 'https://badtype.example/' }, expectOpen: true },
    { name: 'unrecognized string', mockResult: { riskLevel: 'UnverifiedOrWeird', url: 'https://weird.example/' }, expectOpen: true },
    { name: 'detector throws error', mockResult: 'THROW', expectOpen: true },
  ];

  const origAnalyzeForMatrix = sandbox.PhishGuardDetector.analyzeUrl;
  for (let idx = 0; idx < classificationMatrix.length; idx++) {
    const cm = classificationMatrix[idx];
    const mTabId = 400 + idx;
    tabRecords.set(mTabId, { id: mTabId, windowId: 1, url: 'about:blank' });
    sandbox.PhishGuardDetector.analyzeUrl = function () {
      if (cm.mockResult === 'THROW') throw new Error('Simulated detector failure');
      return cm.mockResult;
    };
    const startLen = updatedTabs.length;
    await listeners.beforeNavigate[0]({ tabId: mTabId, frameId: 0, url: `https://case-${idx}.example/` });
    await new Promise((r) => setTimeout(r, 30));
    const opened = updatedTabs
      .slice(startLen)
      .some((u) => u.id === mTabId && u.patch.url && u.patch.url.startsWith('chrome-extension://test-ext-id/index.html?mode=warning'));
    assert.equal(opened, cm.expectOpen, `Classification "${cm.name}" warning expectation mismatch`);
  }
  sandbox.PhishGuardDetector.analyzeUrl = origAnalyzeForMatrix;

  // 4. Prove repeated URL submissions & visits are independently analyzed with ZERO stored URL cache
  let freshRuleCalls = 0;
  const origAnalyze = sandbox.PhishGuardDetector.analyzeUrl;
  sandbox.PhishGuardDetector.analyzeUrl = function (...args) {
    freshRuleCalls += 1;
    return origAnalyze.apply(this, args);
  };
  await sendMessageToBg({ type: 'PHISHGUARD_MANUAL_SCAN', url: 'https://example.com/' });
  await sendMessageToBg({ type: 'PHISHGUARD_MANUAL_SCAN', url: 'https://example.com/' });
  await listeners.beforeNavigate[0]({ tabId: 101, frameId: 0, url: 'https://example.com/' });
  await new Promise((r) => setTimeout(r, 40));
  await listeners.beforeNavigate[0]({ tabId: 101, frameId: 0, url: 'https://example.com/' });
  await new Promise((r) => setTimeout(r, 40));
  sandbox.PhishGuardDetector.analyzeUrl = origAnalyze;
  assert.equal(freshRuleCalls, 4, 'Every submitted or navigated URL must run independent rule evaluation');
});

test('Interface selection enforces 4 internal outcomes (SAFE, SUSPICIOUS, PHISHING, UNVERIFIED) across Detector, app.js, scanner.js, and background.js', async () => {
  // 1. Ordinary/unfamiliar websites resolve to SAFE (uiState="safe"); threats/failures use warning UI
  for (const safeUrl of [
    'https://example.com/',
    'http://example.com/',
    'https://github.com/login',
    'https://unknown-local-bakery.org/menu',
    'https://unfamiliar-small-business-store.com/products/coffee-beans?page=2&sort=price',
  ]) {
    const res = Detector.analyzeUrl(safeUrl);
    assert.equal(res.classification, 'SAFE', `Expected SAFE for ${safeUrl}, got ${res.classification}`);
    assert.equal(res.uiState, 'safe', `Expected uiState="safe" for ${safeUrl}`);
  }

  for (const warnUrl of [
    'https://paypa1.com/',
    'https://paypa1.com/login',
    '',
    null,
  ]) {
    const res = Detector.analyzeUrl(warnUrl);
    assert.equal(res.uiState, 'phishing', `Expected Detector uiState="phishing" for ${String(warnUrl)}, got ${res.uiState}`);
  }

  // Minimal DOM Element builder for app.js & scanner.js
  function createMockElement(tagName, id) {
    const classes = new Set();
    const attrs = {};
    const children = [];
    const el = {
      tagName: String(tagName || 'DIV').toUpperCase(),
      id: id || '',
      style: {},
      className: '',
      textContent: '',
      innerHTML: '',
      value: '',
      hidden: false,
      disabled: false,
      tabIndex: 0,
      children,
      classList: {
        add: (...names) => {
          for (const n of names) if (n) classes.add(n);
          el.className = Array.from(classes).join(' ');
        },
        remove: (...names) => {
          for (const n of names) classes.delete(n);
          el.className = Array.from(classes).join(' ');
        },
        toggle: (name, force) => {
          const on = force !== undefined ? Boolean(force) : !classes.has(name);
          if (on) classes.add(name);
          else classes.delete(name);
          el.className = Array.from(classes).join(' ');
          return on;
        },
        contains: (name) => classes.has(name),
      },
      setAttribute: (k, v) => {
        attrs[k] = String(v);
        if (k === 'class') {
          classes.clear();
          String(v).split(/\s+/).filter(Boolean).forEach((c) => classes.add(c));
          el.className = Array.from(classes).join(' ');
        }
      },
      getAttribute: (k) => (k in attrs ? attrs[k] : null),
      removeAttribute: (k) => {
        delete attrs[k];
      },
      addEventListener: () => {},
      appendChild: (child) => {
        children.push(child);
        return child;
      },
      querySelector: () => null,
      querySelectorAll: () => [],
      remove: () => {},
      focus: () => {},
      play: () => Promise.resolve(),
      load: () => {},
    };
    return el;
  }

  function createAppSandbox(options = {}) {
    const byId = new Map();
    const allIds = [
      'panelAccentWash', 'panelStage', 'bgVideo', 'bgVideoSafe', 'panelBgVideo', 'panelBgVideoSafe',
      'headerSubtitle', 'statusHeaderControls', 'scannerHeaderControls', 'panelFooterText',
      'currentUrlField', 'statusSection', 'statusIconWrapper', 'statusTitle', 'statusDetail',
      'riskLevel', 'detectedDomainField', 'impersonatedBrandItem', 'impersonatedBrandField',
      'checksHeading', 'checksList', 'recBody', 'actionSection', 'panelBody', 'confirmationView',
      'scannerView', 'scannerUrlInput', 'btnBackToSafety', 'btnDismissAnyway', 'btnStatePhishing',
      'btnStateSafe', 'avoidBtn', 'closeBtn', 'settingsIcon', 'openScannerBtn',
      'scannerBody', 'scannerForm', 'scannerScanBtn', 'scannerClearBtn', 'scannerValidationError',
      'scannerLoadingState', 'scannerEmptyHint', 'scannerResultsBox', 'scannerVerdictCard',
      'scannerVerdictIconWrapper', 'classificationBadge', 'scannerVerdictTitle', 'scannerVerdictExplanation',
      'scannedUrlDisplay', 'detectedDomainDisplay', 'scannerImpersonatedBrandRow', 'scannerImpersonatedBrand',
      'scannerRecommendation', 'reasonsHeading', 'reasonsList', 'featuresSummaryGrid', 'scannerBackBtn',
      'scannerOpenTabBtn', 'panelSubtitle',
    ];
    for (const id of allIds) {
      byId.set(id, createMockElement('div', id));
    }
    const bgVideo = byId.get('bgVideo');
    bgVideo.querySelector = () => ({ src: './spam_bg.mp4', setAttribute: () => {}, getAttribute: () => './spam_bg.mp4' });
    const panelBgVideo = byId.get('panelBgVideo');
    panelBgVideo.querySelector = () => ({ src: './spam_central_bg.mp4', setAttribute: () => {}, getAttribute: () => './spam_central_bg.mp4' });

    const bodyEl = createMockElement('body');
    bodyEl.classList.add('state-phishing', 'pg-booting');
    const panelEl = createMockElement('main');
    panelEl.classList.add('extension-panel', 'state-phishing');
    const docEl = createMockElement('html');

    const domListeners = {};
    const runtimeMessageHandlers = [];
    const tabActivatedListeners = [];
    const tabUpdatedListeners = [];
    let closedCount = 0;

    const mockChrome = options.chrome || {
      runtime: {
        id: 'test-ext-id',
        lastError: null,
        getURL: (p) => `chrome-extension://test-ext-id/${p}`,
        sendMessage: (msg, cb) => {
          const reply = options.onRuntimeMessage ? options.onRuntimeMessage(msg) : { ok: true, result: null };
          if (typeof cb === 'function') cb(reply);
        },
        onMessage: { addListener: (fn) => runtimeMessageHandlers.push(fn) },
      },
      tabs: {
        query: (_q, cb) => {
          const rows = [options.activeTab || { id: 1, windowId: 1, url: 'https://example.com/' }];
          if (typeof cb === 'function') cb(rows);
          return Promise.resolve(rows);
        },
        get: (id, cb) => {
          const row = options.getTab ? options.getTab(id) : { id, url: 'https://example.com/' };
          if (typeof cb === 'function') cb(row);
          return Promise.resolve(row);
        },
        onUpdated: { addListener: (fn) => tabUpdatedListeners.push(fn) },
        onActivated: { addListener: (fn) => tabActivatedListeners.push(fn) },
      },
    };

    const documentMock = {
      title: '',
      body: bodyEl,
      documentElement: docEl,
      createElement: (tag) => createMockElement(tag),
      getElementById: (id) => byId.get(id) || null,
      querySelector: (sel) => (sel === '.extension-panel' ? panelEl : null),
      querySelectorAll: () => [],
      addEventListener: (evt, fn) => {
        domListeners[evt] = domListeners[evt] || [];
        domListeners[evt].push(fn);
      },
    };

    const windowMock = {
      location: { search: options.search || '?mode=popup', href: '' },
      document: documentMock,
      history: { replaceState: () => {}, length: 1, back: () => {} },
      close: () => {
        closedCount += 1;
      },
      PhishGuardBrandDetector: BrandDetector,
      PhishGuardURLAnalyzer: URLAnalyzer,
      PhishGuardRuleEngine: RuleEngine,
      PhishGuardRiskScorer: RiskScorer,
      PhishGuardDetector: Detector,
      requestAnimationFrame: (fn) => fn(),
    };
    windowMock.window = windowMock;

    const sb = {
      window: windowMock,
      document: documentMock,
      chrome: mockChrome,
      URL,
      URLSearchParams,
      console,
      setTimeout,
      clearTimeout,
      requestAnimationFrame: windowMock.requestAnimationFrame,
    };
    vm.createContext(sb);
    vm.runInContext(fs.readFileSync(path.join(EXT_ROOT, 'src', 'app.js'), 'utf8'), sb, { filename: 'src/app.js' });
    vm.runInContext(fs.readFileSync(path.join(EXT_ROOT, 'src', 'scanner.js'), 'utf8'), sb, { filename: 'src/scanner.js' });
    return {
      app: windowMock.PhishGuard,
      scanner: windowMock.PhishGuardScanner,
      byId,
      bodyEl,
      panelEl,
      domListeners,
      tabActivatedListeners,
      tabUpdatedListeners,
      getClosedCount: () => closedCount,
    };
  }

  // 2. Test app.js UI state selection across exact "Safe" vs all non-Safe inputs
  const appEnv = createAppSandbox({
    search: '?mode=popup',
    onRuntimeMessage: () => ({
      ok: true,
      result: { outcome: 'SAFE', classification: 'SAFE', riskLevel: 'Safe', url: 'https://verified.example/', supported: true },
    }),
  });
  for (const fn of appEnv.domListeners.DOMContentLoaded || []) {
    await fn();
  }
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(appEnv.app.getState(), 'safe');
  assert.equal(appEnv.panelEl.classList.contains('state-safe'), true);
  assert.equal(appEnv.panelEl.classList.contains('state-phishing'), false);
  assert.equal(appEnv.byId.get('statusSection').className.includes('status-safe'), true);
  assert.equal(appEnv.byId.get('btnStateSafe').hidden, false);
  assert.equal(appEnv.byId.get('btnStatePhishing').hidden, true);
  assert.equal(appEnv.byId.get('riskLevel').textContent, 'SAFE');
  assert.equal(appEnv.byId.get('actionSection').style.display, 'none');
  assert.equal(appEnv.getClosedCount(), 0);

  const nonSafeAppInputs = [
    { name: 'SUSPICIOUS (Detector)', input: Detector.analyzeUrl('https://paypa1.com/'), expectBadge: 'SUSPICIOUS', expectTitle: 'Suspicious URL Detected' },
    { name: 'PHISHING (Detector)', input: Detector.analyzeUrl('https://paypa1.com/login'), expectBadge: 'HIGH RISK', expectTitle: 'Potential Phishing Detected' },
    { name: 'UNVERIFIED (Detector failed)', input: Detector.analyzeUrl('not a valid ::: url'), expectBadge: 'UNVERIFIED', expectTitle: 'Unable to Verify URL' },
    { name: 'UNVERIFIED (explicit)', input: { outcome: 'UNVERIFIED', classification: 'UNVERIFIED', riskLevel: 'Unverified', supported: true }, expectBadge: 'UNVERIFIED', expectTitle: 'Unable to Verify URL' },
    { name: 'null result', input: null, expectBadge: 'UNVERIFIED', expectTitle: 'Unable to Verify URL' },
    { name: 'undefined result', input: undefined, expectBadge: 'UNVERIFIED', expectTitle: 'Unable to Verify URL' },
    { name: 'empty object', input: {}, expectBadge: 'UNVERIFIED', expectTitle: 'Unable to Verify URL' },
    { name: 'empty classification', input: { riskLevel: '', classification: '' }, expectBadge: 'UNVERIFIED', expectTitle: 'Unable to Verify URL' },
    { name: 'invalid classification string', input: { riskLevel: 'BogusStatus', supported: true }, expectBadge: 'UNVERIFIED', expectTitle: 'Unable to Verify URL' },
    { name: 'numeric classification', input: { riskLevel: 42, classification: 99 }, expectBadge: 'UNVERIFIED', expectTitle: 'Unable to Verify URL' },
  ];

  for (const tc of nonSafeAppInputs) {
    appEnv.app.applyDetectionResult(tc.input, { skipTransition: true });
    assert.equal(appEnv.app.getState(), 'phishing', `app.js must NOT show Safe state for ${tc.name}`);
    assert.equal(appEnv.panelEl.classList.contains('state-phishing'), true, `panel missing state-phishing for ${tc.name}`);
    assert.equal(appEnv.panelEl.classList.contains('state-safe'), false, `panel wrongly has state-safe for ${tc.name}`);
    assert.equal(appEnv.byId.get('statusSection').className.includes('status-phishing'), true, `statusSection not status-phishing for ${tc.name}`);
    assert.equal(appEnv.byId.get('statusSection').className.includes('status-safe'), false, `statusSection wrongly status-safe for ${tc.name}`);
    assert.equal(appEnv.byId.get('btnStateSafe').hidden, true, `Safe pill shown for ${tc.name}`);
    assert.equal(appEnv.byId.get('btnStatePhishing').hidden, false, `Warning pill hidden for ${tc.name}`);
    assert.equal(appEnv.byId.get('riskLevel').textContent, tc.expectBadge, `Unexpected badge for ${tc.name}`);
    assert.equal(appEnv.byId.get('statusTitle').textContent, tc.expectTitle, `Unexpected statusTitle for ${tc.name}`);
    assert.equal(appEnv.byId.get('actionSection').style.display, 'flex', `Actions hidden for ${tc.name}`);
  }

  // Ordinary SAFE URLs render Safe UI directly
  for (const safeUrl of ['https://example.com/', 'http://example.com/', 'https://unknown-local-bakery.org/menu']) {
    appEnv.app.applyDetectionResult(Detector.analyzeUrl(safeUrl), { skipTransition: true });
    assert.equal(appEnv.app.getState(), 'safe', `Expected SAFE state for ${safeUrl}`);
    assert.equal(appEnv.panelEl.classList.contains('state-safe'), true);
    assert.equal(appEnv.panelEl.classList.contains('state-phishing'), false);
    assert.equal(appEnv.byId.get('riskLevel').textContent, 'SAFE');
  }

  // Exempt browser-internal, PDF-viewer, and local file:// pages render NEUTRAL exempt notice (never Safe, never Phishing)
  for (const exemptUrl of [
    'chrome://extensions',
    'chrome-extension://mhjfbmdgcfjbbpaeojofohoefgiehjai/index.html',
    'edge://settings',
    'about:blank',
    'file:///C:/Users/hp/Documents/report.pdf',
  ]) {
    appEnv.app.applyDetectionResult(Detector.analyzeUrl(exemptUrl), { skipTransition: true });
    assert.equal(appEnv.app.getState(), 'neutral', `Expected neutral state for exempt ${exemptUrl}`);
    assert.equal(appEnv.panelEl.classList.contains('state-neutral'), true);
    assert.equal(appEnv.panelEl.classList.contains('state-safe'), false);
    assert.equal(appEnv.panelEl.classList.contains('state-phishing'), false);
    assert.equal(appEnv.byId.get('btnStateSafe').hidden, true);
    assert.equal(appEnv.byId.get('btnStatePhishing').hidden, true);
    assert.equal(appEnv.byId.get('riskLevel').textContent, 'EXEMPT');
    assert.equal(appEnv.byId.get('actionSection').style.display, 'none');
  }

  // 3. Test popup mode closes immediately when background redirected non-Safe active tab to full-page warning (never shows both interfaces)
  let currentActiveUrl = 'https://example.com/';
  const popupEnv = createAppSandbox({
    search: '?mode=popup',
    activeTab: { id: 77, windowId: 1, url: currentActiveUrl },
    getTab: (id) => ({ id, windowId: 1, url: currentActiveUrl }),
    onRuntimeMessage: (msg) => {
      if (msg && msg.type === 'PHISHGUARD_GET_TAB_STATUS') {
        const evaluated = Detector.analyzeUrl(currentActiveUrl);
        return {
          ok: true,
          result: { ...evaluated, blocked: evaluated.classification !== 'SAFE' },
          dismissed: false,
        };
      }
      return { ok: true };
    },
  });
  for (const fn of popupEnv.domListeners.DOMContentLoaded || []) {
    await fn();
  }
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(popupEnv.app.getState(), 'safe');
  assert.equal(popupEnv.getClosedCount(), 0);

  // 3b. Popup boot never flashes state-phishing or "Potential Phishing Detected" before settling
  const indexHtmlSrc = fs.readFileSync(path.join(EXT_ROOT, 'index.html'), 'utf8');
  assert.equal(/<body[^>]*state-phishing/i.test(indexHtmlSrc), false, 'index.html must not hardcode state-phishing on body');
  assert.equal(/<main[^>]*state-phishing/i.test(indexHtmlSrc), false, 'index.html must not hardcode state-phishing on panel');
  assert.equal(indexHtmlSrc.includes('Potential Phishing Detected'), false, 'index.html must not hardcode phishing headline before detection');

  const bootDocClasses = new Set();
  const bootSandbox = {
    URLSearchParams,
    window: { location: { search: '?mode=popup' } },
    document: {
      documentElement: {
        classList: {
          add: (c) => bootDocClasses.add(c),
          remove: (c) => bootDocClasses.delete(c),
          contains: (c) => bootDocClasses.has(c),
        },
      },
    },
    setTimeout: () => 0,
  };
  vm.createContext(bootSandbox);
  vm.runInContext(fs.readFileSync(path.join(EXT_ROOT, 'src', 'popupBoot.js'), 'utf8'), bootSandbox, { filename: 'src/popupBoot.js' });
  assert.equal(bootDocClasses.has('pg-popup'), true);
  assert.equal(bootDocClasses.has('pg-hydrating'), true);

  // Active tab changes to a SUSPICIOUS site -> popup updates away from Safe and closes since warning page opened
  currentActiveUrl = 'https://paypa1.com/';
  await popupEnv.tabActivatedListeners[0]({ tabId: 78 });
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(popupEnv.app.getState(), 'phishing');
  assert.equal(popupEnv.panelEl.classList.contains('state-safe'), false);
  assert.equal(popupEnv.getClosedCount(), 1);

  // 4. Test background.js setPopup + tabs.onActivated after startup_scan (non-Safe must clear popup and activate full-page warning)
  const bgListeners = { onActivated: [], onMessage: [] };
  const popupCalls = [];
  const bgUpdatedTabs = [];
  const bgTabs = new Map([[901, { id: 901, windowId: 1, url: 'https://paypa1.com/' }], [902, { id: 902, windowId: 1, url: 'https://example.com/' }]]);
  const bgSandbox = {
    console, Date, Math, Set, Map, Array, Object, String, Number, Boolean, RegExp, Error, Promise, JSON,
    URL, URLSearchParams, atob, btoa, encodeURIComponent, decodeURIComponent, setTimeout, clearTimeout,
    chrome: {
      runtime: {
        lastError: null,
        getURL: (rel) => `chrome-extension://test-ext-id/${rel}`,
        onInstalled: { addListener: () => {} },
        onStartup: { addListener: () => {} },
        onMessage: { addListener: (fn) => bgListeners.onMessage.push(fn) },
        onMessageExternal: { addListener: () => {} },
      },
      storage: { session: { get: async () => ({}), set: async () => {} } },
      webNavigation: {
        onBeforeNavigate: { addListener: () => {} },
        onCommitted: { addListener: () => {} },
        onHistoryStateUpdated: { addListener: () => {} },
        onReferenceFragmentUpdated: { addListener: () => {} },
      },
      tabs: {
        query: async () => Array.from(bgTabs.values()),
        get: async (id) => bgTabs.get(id) || null,
        update: async (id, patch) => {
          bgUpdatedTabs.push({ id, patch });
          const cur = bgTabs.get(id) || { id };
          bgTabs.set(id, { ...cur, ...patch });
          return bgTabs.get(id);
        },
        create: async (p) => p,
        onUpdated: { addListener: () => {} },
        onActivated: { addListener: (fn) => bgListeners.onActivated.push(fn) },
        onRemoved: { addListener: () => {} },
      },
      windows: { update: async () => {} },
      action: {
        setPopup: async (info) => popupCalls.push(info),
        setIcon: async () => {},
        setTitle: async () => {},
        setBadgeText: async () => {},
        setBadgeBackgroundColor: async () => {},
        onClicked: { addListener: () => {} },
      },
    },
    importScripts: (...relPaths) => {
      for (const rel of relPaths) {
        const cleanRel = rel.replace(/^\.\//, '');
        vm.runInContext(fs.readFileSync(path.join(EXT_ROOT, cleanRel), 'utf8'), bgSandbox, { filename: cleanRel });
      }
    },
  };
  bgSandbox.globalThis = bgSandbox;
  bgSandbox.self = bgSandbox;
  vm.createContext(bgSandbox);
  vm.runInContext(fs.readFileSync(path.join(EXT_ROOT, 'background.js'), 'utf8'), bgSandbox, { filename: 'background.js' });

  // Startup scan caches SUSPICIOUS & SAFE without redirecting; switching to SUSPICIOUS tab 901 must trigger warning while SAFE tab 902 allows browsing
  await bgSandbox.scanExistingOpenTabs();
  await bgListeners.onActivated[0]({ tabId: 901 });
  await bgListeners.onActivated[0]({ tabId: 902 });
  await new Promise((r) => setTimeout(r, 40));
  assert.ok(
    bgUpdatedTabs.some((u) => u.id === 901 && u.patch.url && u.patch.url.startsWith('chrome-extension://test-ext-id/index.html?mode=warning')),
    'Activating a SUSPICIOUS tab must open the full-page phishing warning interface'
  );
  assert.equal(
    bgUpdatedTabs.some((u) => u.id === 902 && u.patch.url && u.patch.url.startsWith('chrome-extension://test-ext-id/index.html?mode=warning')),
    false,
    'Activating an unfamiliar SAFE site must allow normal browsing'
  );
  assert.equal(popupCalls.filter((c) => c.tabId === 901).pop().popup, '');
  assert.equal(popupCalls.filter((c) => c.tabId === 902).pop().popup, 'index.html?mode=popup');

  // syncPopupForTab permits popup ONLY for SAFE outcome
  popupCalls.length = 0;
  await bgSandbox.syncPopupForTab(902, { outcome: 'SAFE', classification: 'SAFE', riskLevel: 'Safe', supported: true }, false);
  assert.equal(popupCalls.pop().popup, 'index.html?mode=popup');
  for (const res of [
    { outcome: 'SUSPICIOUS', classification: 'SUSPICIOUS', riskLevel: 'Suspicious', supported: true },
    { outcome: 'PHISHING', classification: 'PHISHING', riskLevel: 'High Risk', supported: true },
    { outcome: 'UNVERIFIED', classification: 'UNVERIFIED', riskLevel: 'Unverified', supported: true },
    null,
    undefined,
    { riskLevel: 'InvalidCls', supported: true },
  ]) {
    await bgSandbox.syncPopupForTab(902, res, false);
    assert.equal(popupCalls.pop().popup, '', `Popup must be suppressed for non-SAFE ${JSON.stringify(res)}`);
  }
});

test('Manual URL Scanner neutral background flow and Open in Full Interface behavior across all 7 scenarios', async () => {
  function createInteractiveElement(tagName, id) {
    const classes = new Set();
    const attrs = {};
    const children = [];
    const events = {};
    const el = {
      tagName: String(tagName || 'DIV').toUpperCase(),
      id: id || '',
      style: {},
      className: '',
      textContent: '',
      innerHTML: '',
      value: '',
      hidden: false,
      disabled: false,
      tabIndex: 0,
      children,
      classList: {
        add: (...names) => {
          for (const n of names) if (n) classes.add(n);
          el.className = Array.from(classes).join(' ');
        },
        remove: (...names) => {
          for (const n of names) classes.delete(n);
          el.className = Array.from(classes).join(' ');
        },
        toggle: (name, force) => {
          const on = force !== undefined ? Boolean(force) : !classes.has(name);
          if (on) classes.add(name);
          else classes.delete(name);
          el.className = Array.from(classes).join(' ');
          return on;
        },
        contains: (name) => classes.has(name),
      },
      setAttribute: (k, v) => {
        attrs[k] = String(v);
      },
      getAttribute: (k) => (k in attrs ? attrs[k] : null),
      removeAttribute: (k) => {
        delete attrs[k];
      },
      addEventListener: (evt, fn) => {
        events[evt] = events[evt] || [];
        events[evt].push(fn);
      },
      trigger: async (evt, payload = {}) => {
        for (const fn of events[evt] || []) {
          await fn({ preventDefault: () => {}, stopPropagation: () => {}, ...payload });
        }
      },
      appendChild: (child) => {
        children.push(child);
        return child;
      },
      querySelector: () => null,
      querySelectorAll: () => [],
      remove: () => {},
      focus: () => {},
      play: () => Promise.resolve(),
      load: () => {},
    };
    return el;
  }

  function createScannerEnv({ search = '', embedded = false, activeTabUrl = 'https://example.com/', onSendMessage = null } = {}) {
    const byId = new Map();
    const ids = [
      'panelAccentWash', 'panelStage', 'bgVideo', 'bgVideoSafe', 'bgVideoPhishing',
      'panelBgVideo', 'panelBgVideoSafe', 'panelBgVideoPhishing', 'headerSubtitle',
      'scannerHeaderSubtitle', 'statusHeaderControls', 'scannerHeaderControls',
      'panelFooterText', 'currentUrlField', 'statusSection', 'statusIconWrapper',
      'statusTitle', 'statusDetail', 'riskLevel', 'detectedDomainField',
      'impersonatedBrandItem', 'impersonatedBrandField', 'checksHeading', 'checksList',
      'recBody', 'actionSection', 'panelBody', 'confirmationView', 'btnBackToSafety',
      'btnDismissAnyway', 'btnStatePhishing', 'btnStateSafe', 'avoidBtn', 'closeBtn',
      'settingsIcon', 'openScannerBtn', 'scannerOutputStage', 'scannerForm',
      'scannerUrlInput', 'scanUrlBtn', 'clearScannerBtn', 'scannerValidationError',
      'scannerLoadingState', 'scannerEmptyHint', 'scannerResults', 'scannerVerdictCard',
      'scannerStatusIconWrapper', 'classificationBadge', 'scannerVerdictTitle',
      'scannerVerdictExplanation', 'detectedUrlDisplay', 'detectedDomainDisplay',
      'impersonatedBrandRow', 'impersonatedBrandDisplay', 'scannerRecommendation',
      'scannerReasonsHeading', 'reasonsList', 'suspiciousFeaturesList',
      'openInTabBtn', 'backToTabBtn',
    ];
    for (const id of ids) {
      if (id === 'scannerView') continue;
      byId.set(id, createInteractiveElement('div', id));
    }
    if (embedded) {
      byId.set('scannerView', createInteractiveElement('div', 'scannerView'));
    } else {
      byId.set('scannerPanel', createInteractiveElement('main', 'scannerPanel'));
    }

    const panelEl = embedded ? createInteractiveElement('main', 'panelMain') : byId.get('scannerPanel');
    const bodyEl = createInteractiveElement('body');
    if (embedded) {
      bodyEl.classList.add('state-phishing', 'pg-booting');
      panelEl.classList.add('extension-panel', 'state-phishing');
    } else {
      bodyEl.classList.add('app-screen', 'state-neutral', 'scanner-screen');
      panelEl.classList.add('extension-panel', 'scanner-panel', 'state-neutral');
    }

    const createdTabs = [];
    const sentMessages = [];
    const domListeners = {};
    const mockChrome = {
      runtime: {
        id: 'test-ext-id',
        lastError: null,
        getURL: (p) => `chrome-extension://test-ext-id/${String(p || '').replace(/^\//, '')}`,
        sendMessage: (msg, cb) => {
          sentMessages.push(msg);
          const reply = onSendMessage
            ? onSendMessage(msg)
            : msg && msg.type === 'PHISHGUARD_MANUAL_SCAN'
              ? { ok: true, result: Detector.analyzeUrl(msg.url) }
              : msg && msg.type === 'PHISHGUARD_GET_TAB_STATUS'
                ? { ok: true, result: Detector.analyzeUrl(msg.url || activeTabUrl), dismissed: false }
                : { ok: true };
          if (typeof cb === 'function') cb(reply);
        },
        onMessage: { addListener: () => {} },
      },
      tabs: {
        create: (props) => {
          createdTabs.push(props);
          return Promise.resolve({ id: 500 + createdTabs.length, ...props });
        },
        query: (_q, cb) => {
          const rows = [{ id: 10, windowId: 1, url: activeTabUrl }];
          if (typeof cb === 'function') cb(rows);
          return Promise.resolve(rows);
        },
        get: (id, cb) => {
          const row = { id, url: activeTabUrl };
          if (typeof cb === 'function') cb(row);
          return Promise.resolve(row);
        },
        onUpdated: { addListener: () => {} },
        onActivated: { addListener: () => {} },
      },
    };

    const documentMock = {
      title: '',
      body: bodyEl,
      documentElement: createInteractiveElement('html'),
      createElement: (tag) => createInteractiveElement(tag),
      getElementById: (id) => byId.get(id) || null,
      querySelector: (sel) => (sel === '.extension-panel' ? panelEl : null),
      querySelectorAll: () => [],
      addEventListener: (evt, fn) => {
        domListeners[evt] = domListeners[evt] || [];
        domListeners[evt].push(fn);
      },
    };
    const windowMock = {
      location: { search, href: `chrome-extension://test-ext-id/${embedded ? 'index.html' : 'scanner.html'}${search}` },
      document: documentMock,
      history: { replaceState: () => {}, length: 1, back: () => {} },
      close: () => {},
      PhishGuardBrandDetector: BrandDetector,
      PhishGuardURLAnalyzer: URLAnalyzer,
      PhishGuardRuleEngine: RuleEngine,
      PhishGuardRiskScorer: RiskScorer,
      PhishGuardDetector: Detector,
      requestAnimationFrame: (fn) => fn(),
    };
    windowMock.window = windowMock;

    const sb = {
      window: windowMock,
      document: documentMock,
      chrome: mockChrome,
      URL,
      URLSearchParams,
      encodeURIComponent,
      decodeURIComponent,
      console,
      setTimeout,
      clearTimeout,
      requestAnimationFrame: windowMock.requestAnimationFrame,
    };
    vm.createContext(sb);
    vm.runInContext(fs.readFileSync(path.join(EXT_ROOT, 'src', 'transitions.js'), 'utf8'), sb, { filename: 'src/transitions.js' });
    if (embedded) {
      vm.runInContext(fs.readFileSync(path.join(EXT_ROOT, 'src', 'app.js'), 'utf8'), sb, { filename: 'src/app.js' });
    }
    vm.runInContext(fs.readFileSync(path.join(EXT_ROOT, 'src', 'scanner.js'), 'utf8'), sb, { filename: 'src/scanner.js' });
    return {
      app: windowMock.PhishGuard || null,
      scanner: windowMock.PhishGuardScanner,
      byId,
      bodyEl,
      panelEl,
      createdTabs,
      sentMessages,
      boot: async () => {
        for (const fn of domListeners.DOMContentLoaded || []) {
          await fn();
        }
        await new Promise((r) => setTimeout(r, 220));
      },
    };
  }

  // Scenario 1: Open Manual Scanner (both embedded from popup and standalone) => neutral background (no red phishing bg)
  const popupScannerEnv = createScannerEnv({ search: '?mode=popup', embedded: true, activeTabUrl: 'https://paypa1.com/login' });
  await popupScannerEnv.boot();
  popupScannerEnv.app.openScanner();
  assert.equal(popupScannerEnv.panelEl.classList.contains('state-neutral'), true, 'Embedded scanner must start neutral');
  assert.equal(popupScannerEnv.panelEl.classList.contains('state-phishing'), false, 'Embedded scanner must not show phishing bg initially');
  assert.equal(popupScannerEnv.panelEl.classList.contains('state-safe'), false, 'Embedded scanner must not show safe bg initially');

  const standaloneIdleEnv = createScannerEnv({ search: '', embedded: false });
  await standaloneIdleEnv.boot();
  assert.equal(standaloneIdleEnv.panelEl.classList.contains('state-neutral'), true, 'Standalone scanner must start neutral');
  assert.equal(standaloneIdleEnv.panelEl.classList.contains('state-phishing'), false);
  assert.equal(standaloneIdleEnv.panelEl.classList.contains('state-safe'), false);

  // Scenario 2: Scan a legitimate URL => stays neutral while scanning, then transitions to Safe background
  let stateDuringLoading = null;
  const safeScanEnv = createScannerEnv({
    search: '?mode=popup',
    embedded: true,
    onSendMessage: (msg) => {
      if (msg && msg.type === 'PHISHGUARD_MANUAL_SCAN') {
        stateDuringLoading = {
          neutral: safeScanEnv.panelEl.classList.contains('state-neutral'),
          phishing: safeScanEnv.panelEl.classList.contains('state-phishing'),
          safe: safeScanEnv.panelEl.classList.contains('state-safe'),
        };
        return { ok: true, result: Detector.analyzeUrl(msg.url) };
      }
      return { ok: true, result: Detector.analyzeUrl('https://example.com/') };
    },
  });
  await safeScanEnv.boot();
  safeScanEnv.app.openScanner();
  safeScanEnv.byId.get('scannerUrlInput').value = 'https://example.com/';
  await safeScanEnv.scanner.scanUrl();
  assert.deepEqual(stateDuringLoading, { neutral: true, phishing: false, safe: false }, 'Must stay neutral while loading');
  assert.equal(safeScanEnv.panelEl.classList.contains('state-safe'), true, 'Safe scan must transition to Safe background');
  assert.equal(safeScanEnv.panelEl.classList.contains('state-neutral'), false);
  assert.equal(safeScanEnv.panelEl.classList.contains('state-phishing'), false);
  assert.equal(safeScanEnv.byId.get('classificationBadge').textContent, 'SAFE');

  // Click Open in Full Interface on previously scanned SAFE URL
  await safeScanEnv.byId.get('openInTabBtn').trigger('click');
  assert.equal(safeScanEnv.createdTabs.length, 1);
  assert.equal(
    safeScanEnv.createdTabs[0].url,
    'chrome-extension://test-ext-id/scanner.html?scanUrl=https%3A%2F%2Fexample.com%2F&autoScan=1'
  );
  assert.equal(safeScanEnv.createdTabs[0].url.startsWith('chrome-extension://test-ext-id/scanner.html'), true, 'Must open extension scanner tab, NOT target website');

  // Scenario 4: Newly opened tab loads SAFE scanUrl cleanly and displays Safe result (never scans chrome-extension://)
  const openedSafeSearch = new URL(safeScanEnv.createdTabs[0].url).search;
  const fullSafeTab = createScannerEnv({ search: openedSafeSearch, embedded: false });
  await fullSafeTab.boot();
  assert.equal(fullSafeTab.byId.get('scannerUrlInput').value, 'https://example.com/');
  assert.equal(fullSafeTab.byId.get('detectedUrlDisplay').textContent, 'https://example.com/');
  assert.equal(fullSafeTab.panelEl.classList.contains('state-safe'), true);
  assert.equal(fullSafeTab.byId.get('classificationBadge').textContent, 'SAFE');
  assert.equal(
    fullSafeTab.sentMessages.some((m) => m.url && String(m.url).startsWith('chrome-extension://')),
    false,
    'Full-interface tab must never send its chrome-extension:// URL to be scanned'
  );

  // Scenario 3: Scan a suspicious URL => Phishing background after completion, neutral while loading, neutral on Clear/UNVERIFIED
  let suspiciousLoadingSnapshot = null;
  const suspScanEnv = createScannerEnv({
    search: '?mode=popup',
    embedded: true,
    onSendMessage: (msg) => {
      if (msg && msg.type === 'PHISHGUARD_MANUAL_SCAN') {
        suspiciousLoadingSnapshot = {
          neutral: suspScanEnv.panelEl.classList.contains('state-neutral'),
          safe: suspScanEnv.panelEl.classList.contains('state-safe'),
          phishing: suspScanEnv.panelEl.classList.contains('state-phishing'),
        };
        return { ok: true, result: Detector.analyzeUrl(msg.url) };
      }
      return { ok: true, result: Detector.analyzeUrl('https://example.com/') };
    },
  });
  await suspScanEnv.boot();
  suspScanEnv.app.openScanner();
  suspScanEnv.byId.get('scannerUrlInput').value = 'https://paypa1.com/login';
  await suspScanEnv.scanner.scanUrl();
  assert.deepEqual(suspiciousLoadingSnapshot, { neutral: true, safe: false, phishing: false });
  assert.equal(suspScanEnv.panelEl.classList.contains('state-phishing'), true, 'Suspicious/phishing scan must transition to phishing bg');
  assert.equal(suspScanEnv.byId.get('classificationBadge').textContent, 'HIGH RISK');

  // Scenario 5: Open previously scanned suspicious URL in Full Interface -> opens scanner.html?scanUrl=...&autoScan=1 and displays Phishing verdict
  await suspScanEnv.byId.get('openInTabBtn').trigger('click');
  assert.equal(suspScanEnv.createdTabs.length, 1);
  assert.equal(
    suspScanEnv.createdTabs[0].url,
    'chrome-extension://test-ext-id/scanner.html?scanUrl=https%3A%2F%2Fpaypa1.com%2Flogin&autoScan=1'
  );
  const fullSuspTab = createScannerEnv({ search: new URL(suspScanEnv.createdTabs[0].url).search, embedded: false });
  await fullSuspTab.boot();
  assert.equal(fullSuspTab.byId.get('scannerUrlInput').value, 'https://paypa1.com/login');
  assert.equal(fullSuspTab.byId.get('detectedUrlDisplay').textContent, 'https://paypa1.com/login');
  assert.equal(fullSuspTab.panelEl.classList.contains('state-phishing'), true);
  assert.equal(fullSuspTab.byId.get('classificationBadge').textContent, 'HIGH RISK');

  // UNVERIFIED outcome in scanner retains neutral background (no red phishing bg) + clear message
  const unverifiedScanner = createScannerEnv({
    search: '?scanUrl=https%3A%2F%2Fexample.com%2F&autoScan=1',
    embedded: false,
    onSendMessage: () => ({
      ok: true,
      result: { outcome: 'UNVERIFIED', classification: 'UNVERIFIED', riskLevel: 'Unverified', riskBadge: 'UNVERIFIED', statusTitle: 'Unable to Verify URL', url: 'https://example.com/', displayUrl: 'https://example.com/', indicators: [] },
    }),
  });
  await unverifiedScanner.boot();
  assert.equal(unverifiedScanner.panelEl.classList.contains('state-neutral'), true, 'UNVERIFIED must retain neutral background');
  assert.equal(unverifiedScanner.panelEl.classList.contains('state-phishing'), false);
  assert.equal(unverifiedScanner.byId.get('classificationBadge').textContent, 'UNVERIFIED');
  assert.equal(unverifiedScanner.byId.get('scannerVerdictTitle').textContent, 'Unable to Verify URL');

  // Clearing results returns cleanly to neutral background
  await fullSuspTab.byId.get('clearScannerBtn').trigger('click');
  assert.equal(fullSuspTab.panelEl.classList.contains('state-neutral'), true);
  assert.equal(fullSuspTab.panelEl.classList.contains('state-phishing'), false);

  // Scenario 6 & 7: Passing chrome-extension:// URL directly or triggering background worker navigation on scanner.html NEVER scans chrome-extension:// or visits target website
  const badParamEnv = createScannerEnv({
    search: '?scanUrl=' + encodeURIComponent('chrome-extension://test-ext-id/scanner.html'),
    embedded: false,
  });
  await badParamEnv.boot();
  assert.equal(badParamEnv.sentMessages.length, 0);
  assert.equal(badParamEnv.panelEl.classList.contains('state-neutral'), true);
  assert.equal(badParamEnv.byId.get('scannerValidationError').style.display, 'block');

  // Also test index.html?mode=scanner&scanUrl=... path in app.js
  const indexScannerEnv = createScannerEnv({
    search: '?mode=scanner&scanUrl=' + encodeURIComponent('https://paypa1.com/'),
    embedded: true,
  });
  await indexScannerEnv.boot();
  assert.equal(indexScannerEnv.app.getActiveInterface(), 'scanner');
  assert.equal(indexScannerEnv.byId.get('scannerUrlInput').value, 'https://paypa1.com/');
  assert.equal(indexScannerEnv.panelEl.classList.contains('state-phishing'), true);
  assert.equal(indexScannerEnv.byId.get('classificationBadge').textContent, 'SUSPICIOUS');
  assert.equal(
    indexScannerEnv.sentMessages.some((m) => m.url && String(m.url).startsWith('chrome-extension://')),
    false
  );

  // Confirm background worker treats chrome-extension://.../scanner.html?... as internal extension UI page without running detector or redirecting
  const swBeforeNavigate = [];
  const swUpdated = [];
  const swTitleUpdates = [];
  const swSandbox = {
    console, Date, Math, Set, Map, Array, Object, String, Number, Boolean, RegExp, Error, Promise, JSON,
    URL, URLSearchParams, atob, btoa, encodeURIComponent, decodeURIComponent, setTimeout, clearTimeout,
    chrome: {
      runtime: {
        lastError: null,
        getURL: (rel) => `chrome-extension://test-ext-id/${String(rel || '').replace(/^\//, '')}`,
        onInstalled: { addListener: () => {} },
        onStartup: { addListener: () => {} },
        onMessage: { addListener: () => {} },
        onMessageExternal: { addListener: () => {} },
      },
      storage: { session: { get: async () => ({}), set: async () => {} } },
      webNavigation: {
        onBeforeNavigate: { addListener: (fn) => swBeforeNavigate.push(fn) },
        onCommitted: { addListener: () => {} },
        onHistoryStateUpdated: { addListener: () => {} },
        onReferenceFragmentUpdated: { addListener: () => {} },
      },
      tabs: {
        query: async () => [],
        get: async (id) => ({ id, url: 'chrome-extension://test-ext-id/scanner.html?scanUrl=https%3A%2F%2Fpaypa1.com%2Flogin&autoScan=1' }),
        update: async (id, patch) => swUpdated.push({ id, patch }),
        create: async (p) => p,
        onUpdated: { addListener: () => {} },
        onActivated: { addListener: () => {} },
        onRemoved: { addListener: () => {} },
      },
      windows: { update: async () => {} },
      action: {
        setPopup: async () => {},
        setIcon: async () => {},
        setTitle: async (info) => swTitleUpdates.push(info),
        setBadgeText: async () => {},
        setBadgeBackgroundColor: async () => {},
        onClicked: { addListener: () => {} },
      },
    },
    importScripts: (...relPaths) => {
      for (const rel of relPaths) {
        vm.runInContext(fs.readFileSync(path.join(EXT_ROOT, rel.replace(/^\.\//, '')), 'utf8'), swSandbox);
      }
    },
  };
  swSandbox.globalThis = swSandbox;
  swSandbox.self = swSandbox;
  vm.createContext(swSandbox);
  vm.runInContext(fs.readFileSync(path.join(EXT_ROOT, 'background.js'), 'utf8'), swSandbox, { filename: 'background.js' });
  let bgAnalyzeCalls = 0;
  const origBgAnalyze = swSandbox.PhishGuardDetector.analyzeUrl;
  swSandbox.PhishGuardDetector.analyzeUrl = (...args) => {
    bgAnalyzeCalls += 1;
    return origBgAnalyze(...args);
  };
  await swBeforeNavigate[0]({
    tabId: 818,
    frameId: 0,
    url: 'chrome-extension://test-ext-id/scanner.html?scanUrl=https%3A%2F%2Fpaypa1.com%2Flogin&autoScan=1',
  });
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(bgAnalyzeCalls, 0, 'Background navigation listener must never run URL detection on chrome-extension:// scanner URL');
  assert.equal(swUpdated.length, 0, 'Opening scanner tab must never redirect or navigate to target website');
  assert.equal(swTitleUpdates.pop().title, 'PhishGuard – Manual URL Scanner');
});

test('Exempt internal browser, extension, Chrome PDF viewer, and local file:// URLs skip phishing rules while external .pdf URLs undergo full analysis', async () => {
  // 1. URLAnalyzer & Detector must exempt internal/local/PDF-viewer schemes BEFORE feature extraction or rule execution
  const exemptUrls = [
    { url: 'chrome://settings', isPdfViewer: false, isLocalFile: false },
    { url: 'chrome://extensions/', isPdfViewer: false, isLocalFile: false },
    { url: 'chrome-extension://abcdef123456/options.html', isPdfViewer: false, isLocalFile: false },
    { url: 'chrome-extension://mhjfbmdgcfjbbpaeojofohoefgiehjai/index.html', isPdfViewer: true, isLocalFile: false },
    { url: 'chrome-extension://mhjfbmdgcfjbbpaeojofohoefgiehjai/content/web/viewer.html?src=report.pdf', isPdfViewer: true, isLocalFile: false },
    { url: 'blob:chrome-extension://mhjfbmdgcfjbbpaeojofohoefgiehjai/7f6d9a1c-0000-4444-8888-abcdef012345', isPdfViewer: true, isLocalFile: false },
    { url: 'edge://settings/profiles', isPdfViewer: false, isLocalFile: false },
    { url: 'edge://pdf/viewer.html', isPdfViewer: true, isLocalFile: false },
    { url: 'about:blank', isPdfViewer: false, isLocalFile: false },
    { url: 'about:srcdoc', isPdfViewer: false, isLocalFile: false },
    { url: 'file:///C:/Users/hp/Documents/quarterly-report.pdf', isPdfViewer: false, isLocalFile: true },
    { url: 'FILE:///C:/Users/hp/Downloads/login-instructions%20(1).pdf', isPdfViewer: false, isLocalFile: true },
    { url: 'file://localhost/tmp/verify-account.pdf', isPdfViewer: false, isLocalFile: true },
    { url: 'blob:file:///d39a1c11-2222-3333-4444-555566667777', isPdfViewer: false, isLocalFile: true },
  ];

  // Ensure RiskScorer.scoreFeatures is NOT invoked for any exempt URL
  let scorerInvocations = 0;
  const origScoreFeatures = RiskScorer.scoreFeatures;
  RiskScorer.scoreFeatures = (...args) => {
    scorerInvocations += 1;
    return origScoreFeatures.apply(RiskScorer, args);
  };
  try {
    for (const tc of exemptUrls) {
      assert.equal(URLAnalyzer.isSupportedUrl(tc.url), false, `isSupportedUrl must be false for ${tc.url}`);
      const scope = URLAnalyzer.classifyExemptUrl(tc.url);
      assert.equal(scope.isExempt, true, `classifyExemptUrl must mark ${tc.url} exempt`);
      assert.equal(scope.isPdfViewer, tc.isPdfViewer, `Unexpected isPdfViewer for ${tc.url}`);
      assert.equal(scope.isLocalFile, tc.isLocalFile, `Unexpected isLocalFile for ${tc.url}`);

      const features = URLAnalyzer.extractFeatures(tc.url);
      assert.equal(features.exempt, true, `extractFeatures must short-circuit exempt ${tc.url}`);
      assert.equal(features.supported, false);

      const res = Detector.analyzeUrl(tc.url);
      assert.equal(res.classification, 'EXEMPT', `Expected EXEMPT for ${tc.url}, got ${res.classification}`);
      assert.notEqual(res.classification, 'SAFE', `Exempt ${tc.url} must not classify as SAFE`);
      assert.notEqual(res.classification, 'PHISHING', `Exempt ${tc.url} must not classify as PHISHING`);
      assert.equal(res.exempt, true);
      assert.equal(res.isInternalBrowserPage, true);
      assert.equal(res.shouldBlock, false, `Exempt ${tc.url} must never trigger warning block`);
      assert.equal(res.uiState, 'neutral', `Exempt ${tc.url} uiState must be neutral`);
      assert.equal(res.rules.length, 0, `Exempt ${tc.url} must execute zero detection rules`);
    }
    assert.equal(scorerInvocations, 0, 'Normal URL risk scoring must NOT run for exempt URLs');
  } finally {
    RiskScorer.scoreFeatures = origScoreFeatures;
  }

  // 2. Ordinary & malicious HTTP/HTTPS URLs containing .pdf or internal strings in path/query MUST still run normal detection!
  const externalPdfCases = [
    { url: 'https://example.com/', expect: 'SAFE', expectBlock: false },
    { url: 'https://example.com/annual-report.pdf', expect: 'SAFE', expectBlock: false },
    { url: 'http://example.com/manual.pdf?download=1', expect: 'SAFE', expectBlock: false },
    { url: 'https://paypa1.com/', expect: 'SUSPICIOUS', expectBlock: true },
    { url: 'https://paypa1.com/login', expect: 'PHISHING', expectBlock: true },
    { url: 'https://verify-billing.tk/invoice.pdf', expect: 'PHISHING', expectBlock: true },
    { url: 'https://billing-notice.example.org/invoice_042.pdf.exe', expect: 'PHISHING', expectBlock: true },
    { url: 'https://verify-account.tk/chrome-extension://mhjfbmdgcfjbbpaeojofohoefgiehjai/doc.pdf', expect: 'PHISHING', expectBlock: true },
    { url: 'https://verify-account.tk/?next=file:///C:/Users/report.pdf', expect: 'PHISHING', expectBlock: true },
  ];

  for (const tc of externalPdfCases) {
    assert.equal(URLAnalyzer.isSupportedUrl(tc.url), true, `External URL must NOT be exempted: ${tc.url}`);
    assert.equal(URLAnalyzer.classifyExemptUrl(tc.url).isExempt, false);
    const res = Detector.analyzeUrl(tc.url);
    assert.equal(res.classification, tc.expect, `Expected ${tc.expect} for ${tc.url}, got ${res.classification} (${res.riskScore})`);
    assert.equal(Boolean(res.exempt), false);
    assert.equal(res.shouldBlock, tc.expectBlock, `Unexpected shouldBlock on ${tc.url}`);
  }

  // 3. Background navigation monitor must never open warning or suppress popup on exempt tabs,
  //    while still warning on malicious external .pdf URLs
  const navListeners = { beforeNavigate: [], committed: [], onUpdated: [], onActivated: [] };
  const navUpdatedTabs = [];
  const navPopupSettings = [];
  const navIcons = [];
  const navTabs = new Map([
    [301, { id: 301, windowId: 1, url: 'file:///C:/Users/hp/Documents/test.pdf' }],
    [302, { id: 302, windowId: 1, url: 'chrome-extension://mhjfbmdgcfjbbpaeojofohoefgiehjai/index.html' }],
    [303, { id: 303, windowId: 1, url: 'chrome://extensions' }],
    [304, { id: 304, windowId: 1, url: 'edge://settings' }],
    [305, { id: 305, windowId: 1, url: 'about:blank' }],
    [306, { id: 306, windowId: 1, url: 'https://example.com/annual-report.pdf' }],
    [307, { id: 307, windowId: 1, url: 'https://verify-billing.tk/invoice.pdf' }],
  ]);
  const navSandbox = {
    console, Date, Math, Set, Map, Array, Object, String, Number, Boolean, RegExp, Error, Promise, JSON,
    URL, URLSearchParams, atob, btoa, encodeURIComponent, decodeURIComponent, setTimeout, clearTimeout,
    chrome: {
      runtime: {
        lastError: null,
        getURL: (rel) => `chrome-extension://test-ext-id/${rel}`,
        onInstalled: { addListener: () => {} },
        onStartup: { addListener: () => {} },
        onMessage: { addListener: () => {} },
        onMessageExternal: { addListener: () => {} },
      },
      storage: { session: { get: async () => ({}), set: async () => {} } },
      webNavigation: {
        onBeforeNavigate: { addListener: (fn) => navListeners.beforeNavigate.push(fn) },
        onCommitted: { addListener: (fn) => navListeners.committed.push(fn) },
        onHistoryStateUpdated: { addListener: () => {} },
        onReferenceFragmentUpdated: { addListener: () => {} },
      },
      tabs: {
        query: async () => Array.from(navTabs.values()),
        get: async (id) => navTabs.get(id) || null,
        update: async (id, patch) => {
          navUpdatedTabs.push({ id, patch });
          const cur = navTabs.get(id) || { id };
          navTabs.set(id, { ...cur, ...patch });
          return navTabs.get(id);
        },
        create: async (p) => p,
        onUpdated: { addListener: (fn) => navListeners.onUpdated.push(fn) },
        onActivated: { addListener: (fn) => navListeners.onActivated.push(fn) },
        onRemoved: { addListener: () => {} },
      },
      windows: { update: async () => {} },
      action: {
        setPopup: async (info) => navPopupSettings.push(info),
        setIcon: async (info) => navIcons.push(info),
        setTitle: async () => {},
        setBadgeText: async () => {},
        setBadgeBackgroundColor: async () => {},
        onClicked: { addListener: () => {} },
      },
    },
    importScripts: (...relPaths) => {
      for (const rel of relPaths) {
        vm.runInContext(fs.readFileSync(path.join(EXT_ROOT, rel.replace(/^\.\//, '')), 'utf8'), navSandbox);
      }
    },
  };
  navSandbox.globalThis = navSandbox;
  navSandbox.self = navSandbox;
  vm.createContext(navSandbox);
  vm.runInContext(fs.readFileSync(path.join(EXT_ROOT, 'background.js'), 'utf8'), navSandbox, { filename: 'background.js' });

  for (const exemptTabId of [301, 302, 303, 304, 305]) {
    const t = navTabs.get(exemptTabId);
    await navListeners.beforeNavigate[0]({ tabId: exemptTabId, frameId: 0, url: t.url });
    await navListeners.committed[0]({ tabId: exemptTabId, frameId: 0, url: t.url, transitionType: 'typed' });
    await navListeners.onUpdated[0](exemptTabId, { status: 'complete' }, t);
    await navListeners.onActivated[0]({ tabId: exemptTabId });
  }
  await new Promise((r) => setTimeout(r, 40));

  assert.equal(
    navUpdatedTabs.filter((u) => u.id >= 301 && u.id <= 305).length,
    0,
    'Exempt internal/local/PDF-viewer tabs must NEVER redirect to phishing warning page'
  );
  for (const exemptTabId of [301, 302, 303, 304, 305]) {
    const lastPopup = navPopupSettings.filter((p) => p.tabId === exemptTabId).pop();
    assert.equal(lastPopup.popup, 'index.html?mode=popup', `Popup must stay available on exempt tab ${exemptTabId}`);
    const lastIcon = navIcons.filter((i) => i.tabId === exemptTabId).pop();
    assert.ok(lastIcon.path['16'].includes('icon-default-16.png'), `Toolbar icon on exempt tab ${exemptTabId} must be neutral default (not safe/danger)`);
  }

  // Ordinary external PDF over HTTPS (tab 306) stays allowed with Safe icon; malicious external PDF URL (tab 307) triggers warning!
  await navListeners.beforeNavigate[0]({ tabId: 306, frameId: 0, url: navTabs.get(306).url });
  await navListeners.beforeNavigate[0]({ tabId: 307, frameId: 0, url: navTabs.get(307).url });
  await new Promise((r) => setTimeout(r, 40));

  assert.equal(navUpdatedTabs.filter((u) => u.id === 306).length, 0, 'Safe HTTPS PDF URL must be analyzed cleanly without warning');
  const safePdfIcon = navIcons.filter((i) => i.tabId === 306).pop();
  assert.ok(safePdfIcon.path['16'].includes('icon-safe-16.png'), 'Safe HTTPS PDF URL should be analyzed normally and show Safe icon');

  const maliciousPdfRedirects = navUpdatedTabs.filter((u) => u.id === 307);
  assert.equal(maliciousPdfRedirects.length, 1, 'Suspicious/phishing external HTTPS .pdf URL must still open warning');
  assert.ok(maliciousPdfRedirects[0].patch.url.includes('index.html?mode=warning'));
});
