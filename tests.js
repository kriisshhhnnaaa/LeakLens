/*
 * LeakLens — test harness (no dependencies).
 *
 * Runs under Node:
 *
 *     node tests.js
 *
 * Exercises the pure detector and redaction functions in detector.js.
 * The UI (script.js) is not loaded here; browser-only behaviour is
 * checked separately. All fixtures are synthetic.
 */
'use strict';

const path = require('path');
const fs = require('fs');

const detectorPath = path.join(__dirname, 'detector.js');

let detector;
try {
  detector = require(detectorPath);
} catch (err) {
  console.error('Could not load detector.js:', err.message);
  process.exit(1);
}

/* ------------------------------------------------------------------ */
/* Tiny assertion helpers                                             */
/* ------------------------------------------------------------------ */

let passed = 0;
let failed = 0;
const failures = [];

function check(name, condition, detail) {
  if (condition) {
    passed += 1;
  } else {
    failed += 1;
    failures.push({ name, detail: detail === undefined ? '' : detail });
  }
}

function eq(name, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  check(
    name,
    ok,
    ok ? '' : `\n      expected: ${JSON.stringify(expected)}\n      actual:   ${JSON.stringify(actual)}`
  );
}

function section(title) {
  process.stdout.write(`\n== ${title}\n`);
}

/* ------------------------------------------------------------------ */
/* Detection: scanText structure                                      */
/* ------------------------------------------------------------------ */

section('scanText structure');

(function () {
  const r = detector.scanText('hello world');
  check('scan returns findings array', Array.isArray(r.findings));
  eq('empty input -> no findings', r.findings.length, 0);
  check('scan reports source length', r.sourceLength === 11, `got ${r.sourceLength}`);
  check('scan reports completion state', r.complete === true, JSON.stringify(r.complete));
})();

(function () {
  const r = detector.scanText('');
  eq('empty string has no findings', r.findings.length, 0);
  eq('empty string length', r.sourceLength, 0);
})();

(function () {
  const r = detector.scanText('   \n\t  ');
  eq('whitespace-only input has no findings', r.findings.length, 0);
})();

/* ------------------------------------------------------------------ */
/* Detection: API-key assignments                                     */
/* ------------------------------------------------------------------ */

section('api-key-assignment');

(function () {
  const src = 'API_KEY=abcd1234efgh5678ijkl9012mnop3456';
  const r = detector.scanText(src);
  const hits = r.findings.filter((f) => f.ruleId === 'api-key-assignment');
  check('detects env-style assignment', hits.length === 1, JSON.stringify(r.findings.map(f => f.ruleId)));
  if (hits.length === 1) {
    eq('offsets slice to the value', src.slice(hits[0].start, hits[0].end), 'abcd1234efgh5678ijkl9012mnop3456');
    check('severity is high', hits[0].severity === 'high', hits[0].severity);
  }
})();

(function () {
  const src = 'API_KEY=SHORT';
  const r = detector.scanText(src);
  eq('short value not flagged', r.findings.filter((f) => f.ruleId === 'api-key-assignment').length, 0);
})();

(function () {
  const src = 'API_KEY=YOUR_API_KEY_HERE';
  const r = detector.scanText(src);
  const hits = r.findings.filter((f) => f.ruleId === 'api-key-assignment');
  check('placeholder value still found but downgraded', hits.length === 1 && hits[0].severity === 'review', JSON.stringify(hits.map((h) => h.severity)));
})();

/* YAML / JSON style */
(function () {
  const src = 'api_key: "kJ9m2pQ7rT4wX6yZ8aB1cD3eF5gH7iJ9"';
  const r = detector.scanText(src);
  const hits = r.findings.filter((f) => f.ruleId === 'api-key-assignment');
  check('detects quoted YAML-style value', hits.length === 1, JSON.stringify(r.findings.map(f => f.ruleId)));
  if (hits.length === 1) {
    eq('redacts inner value, keeps quotes', src.slice(hits[0].start, hits[0].end), 'kJ9m2pQ7rT4wX6yZ8aB1cD3eF5gH7iJ9');
  }
})();

/* Value at end of input */
(function () {
  const src = 'ACCESS_TOKEN=tok_99f88e77d6c5b4a3';
  const r = detector.scanText(src);
  const hits = r.findings.filter((f) => f.ruleId === 'access-token-assignment');
  check('access token at end of input detected', hits.length === 1, JSON.stringify(r.findings.map((f) => f.ruleId)));
  if (hits.length === 1) {
    eq('end-of-source range is exact', src.slice(hits[0].start, hits[0].end), 'tok_99f88e77d6c5b4a3');
    eq('end offset equals source length', hits[0].end, src.length);
  }
})();

/* Multiple occurrences */
(function () {
  const src = 'API_KEY=aaaa1111bbbb2222cccc3333dddd4444\nOTHER=x\nDB_PASSWORD=eeee5555ffff6666gggg7777hhhh8888';
  const r = detector.scanText(src);
  const assignments = r.findings.filter((f) => f.ruleId === 'api-key-assignment' || f.ruleId === 'password-assignment');
  check('multiple assignments all found', assignments.length >= 2, `got ${assignments.length}`);
})();

/* Not a finding: variable name alone */
(function () {
  const r = detector.scanText('The API_KEY variable is documented here.');
  eq('bare variable name not flagged', r.findings.filter((f) => f.ruleId === 'api-key-assignment').length, 0);
})();

/* ------------------------------------------------------------------ */
/* Bearer tokens                                                      */
/* ------------------------------------------------------------------ */

section('bearer-token');

(function () {
  const src = 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const r = detector.scanText(src);
  const hits = r.findings.filter((f) => f.ruleId === 'bearer-token');
  check('detects bearer header', hits.length >= 1, JSON.stringify(r.findings.map((f) => f.ruleId)));
  if (hits.length >= 1) {
    check('bearer range starts at the token value', src.slice(hits[0].start, hits[0].end).startsWith('eyJ'), src.slice(hits[0].start, hits[0].end));
  }
})();

(function () {
  const r = detector.scanText('the bearer of bad news arrived today');
  eq('prose with word bearer not flagged', r.findings.filter((f) => f.ruleId === 'bearer-token').length, 0);
})();

/* ------------------------------------------------------------------ */
/* JWT-like tokens                                                    */
/* ------------------------------------------------------------------ */

section('jwt-like-token');

(function () {
  const src = 'token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const r = detector.scanText(src);
  const hits = r.findings.filter((f) => f.ruleId === 'jwt-like-token');
  check('detects three-segment JWT-like string', hits.length >= 1, JSON.stringify(r.findings.map((f) => f.ruleId)));
  if (hits.length >= 1) {
    check('jwt severity is high or review', hits[0].severity === 'high' || hits[0].severity === 'review', hits[0].severity);
  }
})();

(function () {
  const r = detector.scanText('version 1.2.3 works fine');
  eq('dotted version numbers not flagged as JWT', r.findings.filter((f) => f.ruleId === 'jwt-like-token').length, 0);
})();

/* ------------------------------------------------------------------ */
/* Cloud access key IDs                                               */
/* ------------------------------------------------------------------ */

section('cloud-access-key-id');

(function () {
  const src = 'aws_access_key_id=AKIAIOSFODNN7EXAMPLE';
  const r = detector.scanText(src);
  const hits = r.findings.filter((f) => f.ruleId === 'cloud-access-key-id');
  check('detects AWS-style access key id', hits.length >= 1, JSON.stringify(r.findings.map((f) => f.ruleId)));
  if (hits.length >= 1) {
    eq('range covers the key id', src.slice(hits[0].start, hits[0].end), 'AKIAIOSFODNN7EXAMPLE');
    check('severity is high or review', hits[0].severity === 'high' || hits[0].severity === 'review', hits[0].severity);
  }
})();

(function () {
  const r = detector.scanText('the word akia appears here');
  eq('lowercase fragment not flagged', r.findings.filter((f) => f.ruleId === 'cloud-access-key-id').length, 0);
})();

/* ------------------------------------------------------------------ */
/* Vendor API-key prefixes                                            */
/* ------------------------------------------------------------------ */

section('vendor-api-key');

(function () {
  // Each fixture is unmistakably synthetic (spells out NOT-REAL).
  const cases = [
    ['OpenAI project key', 'OPENAI_API_KEY=' + 'sk-proj-' + 'NOTREALkey0123456789abcdefghij0123456789abcd', 'sk-proj-'],
    ['Anthropic key', 'sk-ant-' + 'api03-NOTREALnotreal-notreal-notreal-NOTREAL12ab', 'sk-ant-'],
    ['Slack bot token', 'xox' + 'b-123456789012-1234567890123-NOTREALTOKENabcdef012345', 'xoxb-'],
    ['Google API key', 'AIza' + 'SyNOTREAL0123456789abcdefghij0123abc', 'AIza'],
    ['GitLab PAT', 'glpat-' + 'NOTREAL0123456789ab', 'glpat-'],
    ['Stripe secret key', 'sk_' + 'live_' + 'NOTREAL0123456789abcdefgh', 'sk_live_'],
    ['npm token', 'npm_' + 'NOTREAL0123456789abcdefghijklmnopqrstuvwxyz', 'npm_'],
    ['SendGrid key', 'SG.' + 'NOTREAL0123456789abcdefghij.NOTREAL0123456789abcdefghij0123456789abc', 'SG.'],
    ['Twilio key', 'SK' + '0123456789abcdef0123456789abcdef', 'SK0'],
    ['Vault token', 'hvs.' + 'NOTREAL0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hvs.']
  ];
  cases.forEach(([label, text, expectStart]) => {
    const r = detector.scanText(text);
    const hits = r.findings.filter((f) => f.ruleId === 'vendor-api-key');
    check(label + ' detected', hits.length >= 1, JSON.stringify(r.findings.map((f) => f.ruleId)));
    if (hits.length >= 1) {
      check(label + ' range starts with prefix',
        text.slice(hits[0].start, hits[0].start + expectStart.length) === expectStart,
        text.slice(hits[0].start, hits[0].end));
      check(label + ' severity high', hits[0].severity === 'high', hits[0].severity);
    }
  });
})();

(function () {
  const r = detector.scanText('just the letters sk- and xox and AIza alone are not tokens');
  eq('bare prefixes not flagged', r.findings.filter((f) => f.ruleId === 'vendor-api-key').length, 0);
})();

(function () {
  const r = detector.scanText('pk_live_publishable_NOTREAL0123456789abcd in a docs page');
  eq('publishable stripe key not flagged', r.findings.filter((f) => f.ruleId === 'vendor-api-key').length, 0);
})();

/* ------------------------------------------------------------------ */
/* Private-key blocks                                                 */
/* ------------------------------------------------------------------ */

section('private-key-block');

const COMPLETE_KEY = [
  '-----BEGIN RSA PRIVATE KEY-----',
  'MIIEpAIBAAKCAQEA7y8fZk2mNo9PqRsT',
  'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4',
  '-----END RSA PRIVATE KEY-----'
].join('\n');

(function () {
  const r = detector.scanText(COMPLETE_KEY);
  const hits = r.findings.filter((f) => f.ruleId === 'private-key-block');
  check('complete block detected', hits.length === 1, `got ${hits.length}`);
  if (hits.length === 1) {
    check('complete block is critical', hits[0].severity === 'critical', hits[0].severity);
    eq('block range starts at BEGIN', src0(COMPLETE_KEY, hits[0]), 0);
    eq('block range ends at END marker', hits[0].end, COMPLETE_KEY.length);
  }
})();

function src0(src, f) {
  return f.start;
}

(function () {
  const incomplete = '-----BEGIN PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7y8fZk2mNo9PqRsT\nrest of file';
  const r = detector.scanText(incomplete);
  const hits = r.findings.filter((f) => f.ruleId === 'private-key-block');
  check('incomplete block flagged as review', hits.length >= 1 && hits[0].severity === 'review', JSON.stringify(hits.map((h) => h.severity)));
  if (hits.length >= 1) {
    eq('incomplete block does not run to EOF', incomplete.slice(hits[0].start, hits[0].end).endsWith('rest of file'), false);
  }
})();

/* ------------------------------------------------------------------ */
/* Database connection strings                                        */
/* ------------------------------------------------------------------ */

section('database-uri-credentials');

(function () {
  const src = 'DATABASE_URL=postgres://alice:s3cretPw@db.example.internal:5432/prod';
  const r = detector.scanText(src);
  const hits = r.findings.filter((f) => f.ruleId === 'database-uri-credentials');
  check('detects postgres URI with credentials', hits.length >= 1, JSON.stringify(r.findings.map((f) => f.ruleId)));
  if (hits.length >= 1) {
    check('range starts at scheme', src.slice(hits[0].start, hits[0].end).startsWith('postgres://'), src.slice(hits[0].start, hits[0].end));
    check('severity is high', hits[0].severity === 'high', hits[0].severity);
  }
})();

(function () {
  const r = detector.scanText('See https://example.com/docs for setup instructions.');
  eq('https URL without credentials not flagged', r.findings.filter((f) => f.ruleId === 'database-uri-credentials').length, 0);
})();

/* ------------------------------------------------------------------ */
/* Emails, phones, IPs                                                */
/* ------------------------------------------------------------------ */

section('personal data');

(function () {
  const src = 'Contact jane.doe+ops@example.com for access.';
  const r = detector.scanText(src);
  const hits = r.findings.filter((f) => f.ruleId === 'email-address');
  check('detects email with plus addressing', hits.length === 1, `got ${hits.length}`);
  if (hits.length === 1) {
    eq('email offsets exact', src.slice(hits[0].start, hits[0].end), 'jane.doe+ops@example.com');
    check('email severity is review', hits[0].severity === 'review', hits[0].severity);
  }
})();

(function () {
  const src = 'Reach me at jane@example.com.';
  const r = detector.scanText(src);
  const hits = r.findings.filter((f) => f.ruleId === 'email-address');
  check('trailing punctuation not consumed', hits.length >= 1 && src.slice(hits[0].start, hits[0].end) === 'jane@example.com', src.slice(hits[0].start, hits[0].end));
})();

(function () {
  const src = 'server 192.0.2.128 responded slowly';
  const r = detector.scanText(src);
  const hits = r.findings.filter((f) => f.ruleId === 'ipv4-address');
  check('documentation-range IP detected', hits.length === 1, `got ${hits.length}`);
  if (hits.length === 1) {
    eq('ip offsets exact', src.slice(hits[0].start, hits[0].end), '192.0.2.128');
    check('ip severity is review', hits[0].severity === 'review', hits[0].severity);
  }
})();

(function () {
  const src = 'release 999.888.777.666 is out';
  const r = detector.scanText(src);
  eq('invalid octets rejected', r.findings.filter((f) => f.ruleId === 'ipv4-address').length, 0);
})();

(function () {
  const src = 'Phone: +1 555 0100 (office line)';
  const r = detector.scanText(src);
  const hits = r.findings.filter((f) => f.ruleId === 'phone-like-value');
  check('phone-like value with context detected', hits.length >= 1, JSON.stringify(r.findings.map((f) => f.ruleId)));
})();

(function () {
  const r = detector.scanText('Room 555 100 has new furniture');
  eq('uncontextualised digits not flagged as phone', r.findings.filter((f) => f.ruleId === 'phone-like-value').length, 0);
})();

/* ------------------------------------------------------------------ */
/* Line / column mapping                                              */
/* ------------------------------------------------------------------ */

section('line and column');

(function () {
  const src = 'first line\nsecond line with API_KEY=abcd1234efgh5678ijkl9012mnop3456\nthird';
  const r = detector.scanText(src);
  const f = r.findings[0];
  check('finding exists for line test', !!f, JSON.stringify(r.findings));
  if (f) {
    eq('line is 2', f.line, 2);
  }
})();

(function () {
  const src = 'a\r\nb\r\nc: jane@example.com';
  const r = detector.scanText(src);
  const f = r.findings.find((x) => x.ruleId === 'email-address');
  check('CRLF: email on line 3', f && f.line === 3, f && `line ${f.line}`);
})();

/* ------------------------------------------------------------------ */
/* Masking                                                            */
/* ------------------------------------------------------------------ */

section('masked preview');

(function () {
  const src = 'API_KEY=abcd1234efgh5678ijkl9012mnop3456';
  const r = detector.scanText(src);
  const f = r.findings[0];
  check('mask hides most of value', f && typeof f.maskedPreview === 'string' && !f.maskedPreview.includes('efgh5678'), f && f.maskedPreview);
  check('mask is short', f && f.maskedPreview.length <= 24, f && f.maskedPreview);
})();

/* ------------------------------------------------------------------ */
/* Overlap policy                                                     */
/* ------------------------------------------------------------------ */

section('overlap policy');

(function () {
  // Bearer + JWT: the token value inside the header matches both rules.
  const src = 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const r = detector.scanText(src);
  const bearer = r.findings.filter((f) => f.ruleId === 'bearer-token');
  check('nested rules produce one merged finding', bearer.length === 1, `got ${bearer.length}`);
  if (bearer.length === 1) {
    check('merged finding keeps both rules', Array.isArray(bearer[0].ruleIds) && bearer[0].ruleIds.includes('bearer-token') && bearer[0].ruleIds.includes('jwt-like-token'), JSON.stringify(bearer[0].ruleIds));
  }
})();

/* ------------------------------------------------------------------ */
/* Redaction                                                          */
/* ------------------------------------------------------------------ */

section('redaction');

(function () {
  const src = 'user alice@example.com logged in from 192.0.2.55';
  const r = detector.scanText(src);
  const email = r.findings.find((f) => f.ruleIds.includes('email-address'));
  const ip = r.findings.find((f) => f.ruleIds.includes('ipv4-address'));
  const out = detector.redact(src, [email], r);
  eq(
    'single email redaction exact',
    out,
    'user [REDACTED_EMAIL] logged in from 192.0.2.55'
  );
  const out2 = detector.redact(src, [email, ip], r);
  eq(
    'two redactions on one line exact',
    out2,
    'user [REDACTED_EMAIL] logged in from [REDACTED_IP_ADDRESS]'
  );
})();

(function () {
  const src = 'API_KEY=abcd1234efgh5678ijkl9012mnop3456';
  const r = detector.scanText(src);
  const f = r.findings[0];
  const out = detector.redact(src, [f], r);
  eq('api key redaction exact', out, 'API_KEY=[REDACTED_API_KEY]');
})();

(function () {
  // Empty selection is a no-op, not an error.
  const src = 'nothing here';
  const r = detector.scanText(src);
  eq('empty selection returns source unchanged', detector.redact(src, [], r), src);
})();

(function () {
  // Invalid range must throw, not corrupt output.
  const src = 'some text';
  const r = detector.scanText(src);
  const fake = { start: 2, end: 100, ruleIds: ['x'], placeholder: '[X]' };
  let threw = false;
  try {
    detector.redact(src, [fake], r);
  } catch (e) {
    threw = true;
  }
  check('invalid range rejected', threw, 'no error thrown');
})();

(function () {
  // Overlapping selected ranges merge into one replacement.
  const src = 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const r = detector.scanText(src);
  const merged = r.findings[0];
  const out = detector.redact(src, [merged], r);
  eq('merged finding redacts once', out, 'Authorization: Bearer [REDACTED_BEARER_TOKEN]');
})();

(function () {
  // Start-of-source and end-of-source ranges.
  const src = 'AKIAIOSFODNN7EXAMPLE is the id';
  const r = detector.scanText(src);
  const f = r.findings.find((x) => x.ruleIds.includes('cloud-access-key-id'));
  check('start-of-source finding exists', !!f, JSON.stringify(r.findings));
  if (f) {
    eq('start-of-source redaction', detector.redact(src, [f], r), '[REDACTED_ACCESS_KEY_ID] is the id');
  }
})();

/* ------------------------------------------------------------------ */
/* Scan order determinism                                             */
/* ------------------------------------------------------------------ */

section('determinism');

(function () {
  const src = [
    'DB_PASSWORD=zzzz9999yyyy8888xxxx7777',
    'email: bob@example.com',
    'host 198.51.100.7'
  ].join('\n');
  const a = detector.scanText(src);
  const b = detector.scanText(src);
  eq('same input -> same finding order', a.findings.map((f) => [f.ruleIds.join('+'), f.start]), b.findings.map((f) => [f.ruleIds.join('+'), f.start]));
  check('findings sorted by position', a.findings.every((f, i, arr) => i === 0 || arr[i - 1].start <= f.start), 'order not positional');
})();

/* ------------------------------------------------------------------ */
/* Regex safety: adversarial input                                    */
/* ------------------------------------------------------------------ */

section('regex safety');

(function () {
  const nasty = 'a'.repeat(50000) + '=====' + 'a'.repeat(50000);
  const t0 = Date.now();
  const r = detector.scanText(nasty);
  const ms = Date.now() - t0;
  check('long non-matching input completes', r.complete === true, 'incomplete');
  check('long input under 2s', ms < 2000, `${ms}ms`);
})();

(function () {
  const repeated = ('Authorization: Bearer ' + 'a'.repeat(60) + '\n').repeat(2000);
  const t0 = Date.now();
  const r = detector.scanText(repeated);
  const ms = Date.now() - t0;
  check('repeated patterns complete', r.complete === true, 'incomplete');
  check('repeated patterns under 2s', ms < 2000, `${ms}ms`);
})();

/* ------------------------------------------------------------------ */
/* Summary                                                            */
/* ------------------------------------------------------------------ */

section('summary');

(function () {
  const src = 'API_KEY=abcd1234efgh5678ijkl9012mnop3456\njane@example.com';
  const r = detector.scanText(src);
  check('counts by severity present', r.counts && typeof r.counts === 'object', JSON.stringify(r.counts));
  check('total matches findings length', r.counts.total === r.findings.length, JSON.stringify(r.counts));
})();

/* ------------------------------------------------------------------ */
/* Result                                                             */
/* ------------------------------------------------------------------ */

process.stdout.write(`\n${passed} passed, ${failed} failed\n`);
if (failures.length) {
  process.stdout.write('\nFailures:\n');
  for (const f of failures) {
    process.stdout.write(`  - ${f.name}${f.detail}\n`);
  }
  process.exit(1);
}
