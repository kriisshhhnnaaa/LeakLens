/*
 * LeakLens — detector.js
 *
 * Pure detection + redaction engine. No DOM, no network, no persistence,
 * no logging of raw values. Deterministic: the same source text and the
 * same rule set produce the same findings, in the same order, every run.
 *
 * Offset convention: zero-based UTF-16 code-unit offsets aligned with
 * JavaScript `String.prototype.slice` — inclusive `start`, exclusive
 * `end`, always against the exact scanned snapshot.
 *
 * Loads in a browser (window.LeakLensDetector) and under Node
 * (module.exports) so the test harness can exercise it without a DOM.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  } else {
    root.LeakLensDetector = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const LIMITS = {
    MAX_SOURCE_LEN: 250000, // characters; enforced by the UI and by scanText
    MAX_FINDINGS: 5000
  };

  const SEVERITY_ORDER = { critical: 0, high: 1, review: 2 };

  /* ==================================================================
   * Line index
   * ================================================================== */

  function buildLineIndex(source) {
    const starts = [0];
    for (let i = 0; i < source.length; i++) {
      const c = source.charCodeAt(i);
      if (c === 13 /* \r */) {
        if (source.charCodeAt(i + 1) === 10) i++; // CRLF is one break
        starts.push(i + 1);
      } else if (c === 10 /* \n */) {
        starts.push(i + 1);
      }
    }
    return starts;
  }

  function lineAt(lineStarts, offset) {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo;
  }

  /** 1-based line; 1-based UTF-16 column (approximate around emoji). */
  function lineColAt(lineStarts, offset) {
    const line = lineAt(lineStarts, offset);
    return { line: line + 1, column: offset - lineStarts[line] + 1 };
  }

  /* ==================================================================
   * Masked previews — never return a full raw value.
   * ================================================================== */

  function maskTail(raw, prefixLen) {
    const s = String(raw);
    if (s.length <= prefixLen + 4) return '•'.repeat(Math.min(s.length, 8));
    const dots = Math.min(s.length - prefixLen, 10);
    return s.slice(0, prefixLen) + '•'.repeat(dots);
  }

  function emailMask(raw) {
    const at = raw.indexOf('@');
    if (at <= 0) return '•'.repeat(Math.min(raw.length, 10));
    const local = raw.slice(0, at);
    const head = local.slice(0, Math.min(2, local.length));
    const dots = Math.max(3, Math.min(local.length - head.length, 6));
    return head + '•'.repeat(dots) + '@' + raw.slice(at + 1);
  }

  function ipMask(raw) {
    const parts = raw.split('.');
    if (parts.length !== 4) return '•'.repeat(8);
    return parts[0] + '.' + parts[1] + '.•••';
  }

  function pemMask(raw) {
    const nl = raw.indexOf('\n');
    const header = (nl === -1 ? raw : raw.slice(0, nl)).slice(0, 30);
    return header + ' •••';
  }

  /* ==================================================================
   * Rule registry
   *
   * Each rule: stable id, category, severity, title, explanation,
   * placeholder, mask, and a matcher. Rules either carry a regex
   * `pattern` (with optional `valueGroup` marking the sensitive span
   * and optional `validate`) or a custom `find(source)` function.
   * ================================================================== */

  const VALUE_ALT = '(?:"([^"\\n]{12,})"|\'([^\'\\n]{12,})\'|([^\\s"\'#]{12,}))';

  function placeholderLike(value) {
    return /YOUR_API_KEY|CHANGEME|CHANGE_ME|REPLACE_?ME|PLACEHOLDER|NOT_A_REAL|NOTAREAL|FAKE|EXAMPLE|DUMMY|REDACTED/i.test(value);
  }

  const RULES = [
    {
      id: 'api-key-assignment',
      category: 'Credentials',
      severity: 'high',
      title: 'API-key assignment',
      explanation:
        'A value is assigned to a name like API_KEY, API_SECRET or CLIENT_SECRET. If this is a real credential, sharing it may let others act as you with that service. Values that look like placeholders (e.g. YOUR_API_KEY_HERE) are downgraded to Review.',
      placeholder: '[REDACTED_API_KEY]',
      mask: (raw) => maskTail(raw, 5),
      pattern: new RegExp(
        '\\b(?:API_KEY|APIKEY|API_SECRET|SERVICE_SECRET|CLIENT_SECRET|SECRET_KEY)\\s*[:=]\\s*' + VALUE_ALT,
        'gdi'
      ),
      valueGroup: 'auto', // first non-undefined of groups 1..3
      placeholderCheck: true
    },
    {
      id: 'access-token-assignment',
      category: 'Credentials',
      severity: 'high',
      title: 'Access-token assignment',
      explanation:
        'A value is assigned to a token-like name (ACCESS_TOKEN, AUTH_TOKEN, API_TOKEN). If genuine, such tokens may grant account or service access until revoked. Placeholder-like values are downgraded to Review.',
      placeholder: '[REDACTED_ACCESS_TOKEN]',
      mask: (raw) => maskTail(raw, 5),
      pattern: new RegExp(
        '\\b(?:ACCESS_TOKEN|AUTH_TOKEN|API_TOKEN|BEARER_TOKEN)\\s*[:=]\\s*' +
          '(?:"([^"\\n]{8,})"|\'([^\'\\n]{8,})\'|([^\\s"\'#]{8,}))',
        'gdi'
      ),
      valueGroup: 'auto',
      placeholderCheck: true
    },
    {
      id: 'password-assignment',
      category: 'Credentials',
      severity: 'high',
      title: 'Password assignment',
      explanation:
        'A value is assigned to a password-like name (PASSWORD, DB_PASSWORD, POSTGRES_PASSWORD, …). If genuine, this is the actual secret. Placeholder-like values are downgraded to Review.',
      placeholder: '[REDACTED_PASSWORD]',
      mask: (raw) => maskTail(raw, 4),
      pattern: new RegExp(
        '\\b(?:PASSWORD|PASSWD|DB_PASSWORD|DATABASE_PASSWORD|POSTGRES_PASSWORD|MYSQL_PASSWORD|REDIS_PASSWORD|MONGO_PASSWORD)\\s*[:=]\\s*' +
          '(?:"([^"\\n]{8,})"|\'([^\'\\n]{8,})\'|([^\\s"\'#]{8,}))',
        'gdi'
      ),
      valueGroup: 'auto',
      placeholderCheck: true
    },
    {
      id: 'bearer-token',
      category: 'Credentials',
      severity: 'high',
      title: 'Bearer token',
      explanation:
        'An Authorization header carries a Bearer credential. If genuine, it may grant access to the service it belongs to until revoked. LeakLens cannot tell whether a token is valid, active, or already expired.',
      placeholder: '[REDACTED_BEARER_TOKEN]',
      mask: (raw) => maskTail(raw, 6),
      pattern: /\bAuthorization\s*["':=]+\s*Bearer\s+([A-Za-z0-9\-._~+/]+=*)/gdi,
      valueGroup: 1
    },
    {
      id: 'jwt-like-token',
      category: 'Credentials',
      severity: 'high',
      title: 'JWT-like token',
      explanation:
        'Three base64url segments separated by dots — the shape a JWT has. Structure only: this does not validate the signature, expiry, issuer, audience, or permissions, and does not prove the value is a real token.',
      placeholder: '[REDACTED_TOKEN]',
      mask: (raw) => maskTail(raw, 6),
      pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g
    },
    {
      id: 'cloud-access-key-id',
      category: 'Credentials',
      severity: 'high',
      title: 'Cloud access-key ID (AWS format)',
      explanation:
        'Matches the documented AWS access-key ID shape (AKIA/ASIA/ABIA/ACCA plus 16 characters). A matching identifier does not prove the key is real, active, or paired with a usable secret. Known documentation examples are downgraded to Review.',
      placeholder: '[REDACTED_ACCESS_KEY_ID]',
      mask: (raw) => maskTail(raw, 8),
      pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g,
      placeholderCheck: true
    },
    {
      id: 'vendor-api-key',
      category: 'Credentials',
      severity: 'high',
      title: 'Vendor API key (well-known prefix)',
      explanation:
        'Matches the documented token shapes of widely used services: OpenAI (sk-proj-…), Anthropic (sk-ant-…), Slack (xox…-…-…), Google API (AIza…), GitLab (glpat-…), Stripe secret/restricted keys (sk_live_/rk_live_…), npm (npm_…), PyPI (pypi-…), SendGrid (SG.…), Twilio (SK…hex), and HashiCorp Vault (hvs.…). A shape match does not prove the key is real, active, or has permissions — validity is never checked. Publishable keys (Stripe pk_live_/pk_test_) are deliberately not flagged: they are meant to be public.',
      placeholder: '[REDACTED_VENDOR_API_KEY]',
      mask: (raw) => maskTail(raw, 8),
      pattern: new RegExp(
        [
          'sk-ant-[A-Za-z0-9_-]{40,120}',
          'sk-proj-[A-Za-z0-9_-]{40,160}',
          'xox[bposar]-[0-9]{8,14}(?:-[0-9]{8,14})?-[A-Za-z0-9]{16,40}',
          'AIza[0-9A-Za-z_-]{33,40}',
          'glpat-[A-Za-z0-9_-]{16,40}',
          '(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,120}',
          'npm_[A-Za-z0-9]{30,50}',
          'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,120}',
          'SG\\.[A-Za-z0-9_-]{16,32}\\.[A-Za-z0-9_-]{22,64}',
          'SK[0-9a-fA-F]{32}',
          'hvs\\.[A-Za-z0-9]{40,120}'
        ].join('|'),
        'g'
      )
    },
    {
      id: 'private-key-block',
      category: 'Credentials',
      severity: 'critical',
      title: 'Private-key block',
      explanation:
        'A PEM-style private-key marker was found. If genuine, private-key material is among the most sensitive things that can be shared and should be rotated, not just removed here. A header without a matching END marker is conservatively bounded to the header line plus one body line and marked Review.',
      placeholder: '[REDACTED_PRIVATE_KEY_BLOCK]',
      mask: pemMask,
      find: findPrivateKeys
    },
    {
      id: 'database-uri-credentials',
      category: 'Credentials',
      severity: 'high',
      title: 'Connection string with embedded credentials',
      explanation:
        'This text resembles a connection URI (postgres, mysql, redis, mongodb, amqp, …) with a username and password before the host. If the value is real it may be sensitive. The whole URI is treated as one range so the host is not left behind; LeakLens does not connect to the host or validate the credentials.',
      placeholder: '[REDACTED_CONNECTION_STRING]',
      mask: (raw) => maskTail(raw, 12),
      find: findDatabaseUris
    },
    {
      id: 'email-address',
      category: 'Personal data',
      severity: 'review',
      title: 'Email address',
      explanation:
        'A practical email-address pattern matched here. An address is personal data and can identify you or your organisation; it is not usually a secret. Common forms are covered; this is not full RFC 5322 compliance.',
      placeholder: '[REDACTED_EMAIL]',
      mask: emailMask,
      // Local part bounded at 64 and labels at 63 (the RFC 5321 / DNS
      // limits) so per-position work is constant: an unbounded `+` here
      // made long text without `@` quadratic.
      pattern: /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,63}/g
    },
    {
      id: 'phone-like-value',
      category: 'Personal data',
      severity: 'review',
      title: 'Phone-like value',
      explanation:
        'A digit run that looks like a phone number, next to a label such as “phone”, “mobile”, “tel”, “contact” or “fax”, or a leading-plus international form. Formatting, IDs and timestamps can overlap this shape; this is a heuristic, not a verified phone number.',
      placeholder: '[REDACTED_PHONE]',
      mask: (raw) => maskTail(raw, 3),
      find: findPhones
    },
    {
      id: 'ipv4-address',
      category: 'Infrastructure',
      severity: 'review',
      title: 'IPv4 address',
      explanation:
        'Four dot-separated octets in valid range (0–255). An address alone can be public, private, or documentation-only, and does not show that a host is internal or sensitive. No DNS, GeoIP or registry lookups are performed.',
      placeholder: '[REDACTED_IP_ADDRESS]',
      mask: ipMask,
      find: findIPv4
    }
  ];

  const RULES_BY_ID = {};
  RULES.forEach((r, i) => {
    r.index = i;
    RULES_BY_ID[r.id] = r;
  });

  /* ==================================================================
   * Custom rule matchers
   * ================================================================== */

  function findPrivateKeys(source) {
    const hits = [];
    const beginRe = /-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----/gi;
    let m;
    while ((m = beginRe.exec(source)) !== null) {
      if (m[0].length === 0) { beginRe.lastIndex++; continue; }
      const start = m.index;
      const label = m[1];
      const endMarker = '-----END ' + label + '-----';
      const rel = source.slice(m.index + m[0].length).toLowerCase().indexOf(endMarker.toLowerCase());
      if (rel !== -1) {
        const end = m.index + m[0].length + rel + endMarker.length;
        hits.push({ start, end, ruleId: 'private-key-block', severity: 'critical' });
        beginRe.lastIndex = end;
      } else {
        // Incomplete block: header line + the one body line after it.
        // Never scan to end-of-file.
        let i = m.index + m[0].length;
        while (i < source.length && source[i] !== '\n' && source[i] !== '\r') i++;
        if (source[i] === '\r' && source[i + 1] === '\n') i += 2;
        else if (i < source.length) i++; // consume the break
        while (i < source.length && source[i] !== '\n' && source[i] !== '\r') i++;
        hits.push({
          start,
          end: i,
          ruleId: 'private-key-block',
          severity: 'review',
          note: 'End marker missing — only the header and one body line are covered.'
        });
      }
    }
    return hits;
  }

  const URI_SCHEMES = 'postgres(?:ql)?|mysql|mariadb|mongodb(?:\\+srv)?|redis|rediss|amqp|mssql|sqlserver|jdbc:[a-z0-9]+';
  const URI_PREFIX = new RegExp('\\b(' + URI_SCHEMES + ')://([^/\\s:@"\']{1,128}):([^/\\s@"\']{1,256})@', 'gi');
  const URI_SAFE = /[A-Za-z0-9\-._~:/?#@!$&,;=%*+]/;

  function findDatabaseUris(source) {
    const hits = [];
    const re = new RegExp(URI_PREFIX.source, URI_PREFIX.flags);
    let m;
    while ((m = re.exec(source)) !== null) {
      if (m[0].length === 0) { re.lastIndex++; continue; }
      let end = m.index + m[0].length;
      // Extend over the rest of the URI token (host/path/query), stopping
      // at whitespace, quotes, or brackets. Trim trailing punctuation so a
      // sentence-ending period is not swallowed.
      while (end < source.length && URI_SAFE.test(source[end])) end++;
      while (end > m.index + m[0].length && /[.,;]/.test(source[end - 1])) end--;
      hits.push({ start: m.index, end, ruleId: 'database-uri-credentials', severity: 'high' });
    }
    return hits;
  }

  function findPhones(source) {
    const hits = [];
    const contextual = /\b(phone|mobile|tel|telephone|contact|fax)\s*[:=]?\s*([+]?\d[\d\s.\-()]{5,20}\d)/gi;
    let m;
    while ((m = contextual.exec(source)) !== null) {
      if (m[0].length === 0) { contextual.lastIndex++; continue; }
      let start = m.index + m[1].length;
      while (start < m.index + m[0].length && /[\s:=]/.test(source[start])) start++;
      let end = m.index + m[0].length;
      while (end > start && /[\s.\-()]$/.test(source.slice(start, end))) end--;
      const digits = (source.slice(start, end).match(/\d/g) || []).length;
      if (digits >= 7 && digits <= 15) {
        hits.push({ start, end, ruleId: 'phone-like-value', severity: 'review' });
      }
    }
    const intl = /(?<![\w+])\+\d{1,3}(?:[\s.\-]?\d){6,14}/g;
    while ((m = intl.exec(source)) !== null) {
      if (m[0].length === 0) { intl.lastIndex++; continue; }
      const digits = (m[0].match(/\d/g) || []).length;
      if (digits >= 8 && digits <= 15) {
        hits.push({ start: m.index, end: m.index + m[0].length, ruleId: 'phone-like-value', severity: 'review' });
      }
    }
    return hits;
  }

  function findIPv4(source) {
    const hits = [];
    const re = /\b(?:(\d{1,3})\.){3}(\d{1,3})\b(?!\.\d)/g;
    let m;
    while ((m = re.exec(source)) !== null) {
      if (m[0].length === 0) { re.lastIndex++; continue; }
      const octets = m[0].split('.').map(Number);
      if (octets.length === 4 && octets.every((o) => o >= 0 && o <= 255)) {
        hits.push({ start: m.index, end: m.index + m[0].length, ruleId: 'ipv4-address', severity: 'review' });
      }
    }
    return hits;
  }

  /* ==================================================================
   * Pattern-rule matcher (regex with optional value group)
   * ================================================================== */

  function findWithPattern(rule, source) {
    const hits = [];
    const re = new RegExp(rule.pattern.source, rule.pattern.flags);
    let m;
    while ((m = re.exec(source)) !== null) {
      if (m[0].length === 0) { re.lastIndex++; continue; }
      let start = m.index;
      let end = m.index + m[0].length;
      if (rule.valueGroup) {
        let gi = rule.valueGroup;
        if (gi === 'auto') {
          gi = m[1] !== undefined ? 1 : m[2] !== undefined ? 2 : 3;
        }
        const idx = m.indices && m.indices[gi];
        const val = m[gi];
        if (!val) continue;
        if (idx) {
          start = idx[0];
          end = idx[1];
        } else {
          // Fallback for engines without the `d` flag.
          start = m.index + m[0].lastIndexOf(val);
          end = start + val.length;
        }
      }
      let severity = rule.severity;
      let note;
      if (rule.placeholderCheck && placeholderLike(source.slice(start, end))) {
        severity = 'review';
        note = 'Value looks like a placeholder, so this is downgraded to Review.';
      }
      hits.push({ start, end, ruleId: rule.id, severity, note });
    }
    return hits;
  }

  /* ==================================================================
   * Merge overlapping hits (documented policy)
   *
   * - Exact duplicate ranges merge into one finding; every involved
   *   rule id is kept, and the primary rule is the one with the highest
   *   severity (registry order breaks ties).
   * - Nested ranges merge into the containing range, same rule union.
   * - Partial overlaps merge into the union range. The preview shows
   *   the actual span, so the scope is always visible.
   * - Merely touching ranges (end === start) stay separate.
   * ================================================================== */

  function mergeHits(hits) {
    const sorted = hits.slice().sort((a, b) => {
      if (a.start !== b.start) return a.start - b.start;
      if (a.end !== b.end) return b.end - a.end;
      return RULES_BY_ID[a.ruleId].index - RULES_BY_ID[b.ruleId].index;
    });
    const merged = [];
    let cur = null;
    for (const h of sorted) {
      if (cur && h.start < cur.end) {
        if (h.end > cur.end) cur.end = h.end;
        if (!cur._ruleIds.includes(h.ruleId)) cur._ruleIds.push(h.ruleId);
        if (h.note && !cur.note) cur.note = h.note;
        cur._severityRank = Math.min(cur._severityRank, SEVERITY_ORDER[h.severity]);
        // Track each rule's own (possibly downgraded) severity.
        const prev = cur._sevByRule[h.ruleId];
        if (prev === undefined || SEVERITY_ORDER[h.severity] < SEVERITY_ORDER[prev]) {
          cur._sevByRule[h.ruleId] = h.severity;
        }
      } else {
        cur = {
          start: h.start,
          end: h.end,
          note: h.note,
          _ruleIds: [h.ruleId],
          _sevByRule: {},
          _severityRank: SEVERITY_ORDER[h.severity]
        };
        cur._sevByRule[h.ruleId] = h.severity;
        merged.push(cur);
      }
    }
    return merged;
  }

  /* ==================================================================
   * scanText
   * ================================================================== */

  function scanText(source) {
    if (typeof source !== 'string') {
      throw new TypeError('scanText expects a string');
    }

    const emptyCounts = { total: 0, critical: 0, high: 0, review: 0, byCategory: {} };
    if (source.length > LIMITS.MAX_SOURCE_LEN) {
      return {
        sourceLength: source.length,
        findings: [],
        counts: emptyCounts,
        complete: false,
        truncated: false,
        error: 'source-too-large',
        rulesRun: []
      };
    }

    const hits = [];
    const rulesRun = [];
    let truncated = false;

    for (const rule of RULES) {
      rulesRun.push(rule.id);
      let ruleHits;
      try {
        ruleHits = rule.find ? rule.find(source) : findWithPattern(rule, source);
      } catch (err) {
        // A failing rule must not look like zero matches.
        return {
          sourceLength: source.length,
          findings: [],
          counts: emptyCounts,
          complete: false,
          truncated: false,
          error: 'rule-failed:' + rule.id,
          rulesRun
        };
      }
      for (const h of ruleHits) {
        if (hits.length >= LIMITS.MAX_FINDINGS) {
          truncated = true;
          break;
        }
        hits.push(h);
      }
      if (truncated) break;
    }

    const lineStarts = buildLineIndex(source);
    const mergedRanges = mergeHits(hits);

    const findings = mergedRanges.map((range, i) => {
      // Primary rule: the involved rule with the most severe *per-hit*
      // severity (placeholder/PEM downgrades apply per match), ties
      // broken by registry order.
      const involved = range._ruleIds
        .map((id) => RULES_BY_ID[id])
        .sort((a, b) => {
          const sa = SEVERITY_ORDER[range._sevByRule[a.id]];
          const sb = SEVERITY_ORDER[range._sevByRule[b.id]];
          if (sa !== sb) return sa - sb;
          return a.index - b.index;
        });
      const primary = involved[0];
      const raw = source.slice(range.start, range.end);
      const { line, column } = lineColAt(lineStarts, range.start);
      return {
        id: 'f' + (i + 1),
        ruleId: primary.id,
        ruleIds: range._ruleIds.slice().sort((a, b) => RULES_BY_ID[a].index - RULES_BY_ID[b].index),
        category: primary.category,
        severity: range._sevByRule[primary.id],
        title: primary.title,
        explanation: primary.explanation,
        start: range.start,
        end: range.end,
        line,
        column,
        maskedPreview: primary.mask(raw),
        placeholder: primary.placeholder,
        note: range.note || undefined
      };
    });

    const counts = { total: findings.length, critical: 0, high: 0, review: 0, byCategory: {} };
    for (const f of findings) {
      counts[f.severity] += 1;
      counts.byCategory[f.category] = (counts.byCategory[f.category] || 0) + 1;
    }

    return {
      sourceLength: source.length,
      findings,
      counts,
      complete: true,
      truncated,
      rulesRun
    };
  }

  /* ==================================================================
   * redact — pure, validated, exact
   * ================================================================== */

  function validateRange(source, f) {
    if (
      !f ||
      typeof f.start !== 'number' || !Number.isInteger(f.start) ||
      typeof f.end !== 'number' || !Number.isInteger(f.end) ||
      f.start < 0 ||
      f.end <= f.start ||
      f.end > source.length
    ) {
      throw new Error('Invalid finding range; refusing to redact. Run a new scan.');
    }
  }

  function redact(source, selectedFindings, scanResult) {
    if (typeof source !== 'string') throw new TypeError('redact expects a source string');
    if (!scanResult || scanResult.sourceLength !== source.length) {
      throw new Error('Scan result does not match this source; run a new scan first.');
    }
    const known = scanResult.findings;
    const selected = (selectedFindings || []).map((f) => {
      if (known.indexOf(f) === -1) {
        throw new Error('Finding does not belong to the current scan; run a new scan and reselect.');
      }
      validateRange(source, f);
      return {
        start: f.start,
        end: f.end,
        placeholder: f.placeholder,
        severity: f.severity,
        span: f.end - f.start
      };
    });

    // Overlap policy for selected targets: union merge, with the
    // placeholder of the longest-span finding (ties: more severe
    // severity, then earliest position). Nothing silently expands —
    // the union is exactly the selected ranges' combined extent.
    selected.sort((a, b) => a.start - b.start || b.end - a.end);
    const targets = [];
    let cur = null;
    for (const t of selected) {
      if (cur && t.start <= cur.end) {
        if (t.end > cur.end) cur.end = t.end;
        if (
          t.span > cur.span ||
          (t.span === cur.span && SEVERITY_ORDER[t.severity] < SEVERITY_ORDER[cur.severity])
        ) {
          cur.placeholder = t.placeholder;
          cur.severity = t.severity;
          cur.span = t.span;
        }
      } else {
        cur = { start: t.start, end: t.end, placeholder: t.placeholder, severity: t.severity, span: t.end - t.start };
        targets.push(cur);
      }
    }

    // Replace in ascending order, rebuilding from untouched slices —
    // the source string is never mutated.
    let out = '';
    let pos = 0;
    for (const t of targets) {
      out += source.slice(pos, t.start) + t.placeholder;
      pos = t.end;
    }
    out += source.slice(pos);
    return out;
  }

  /* ==================================================================
   * Exports
   * ================================================================== */

  return {
    LIMITS,
    RULES,
    RULES_BY_ID,
    scanText,
    redact,
    buildLineIndex,
    lineColAt,
    maskedPreview: function (source, finding) {
      const rule = RULES_BY_ID[finding.ruleId] || RULES_BY_ID[finding.ruleIds[0]];
      return rule && rule.mask
        ? rule.mask(source.slice(finding.start, finding.end))
        : maskTail(source.slice(finding.start, finding.end), 4);
    }
  };
});
