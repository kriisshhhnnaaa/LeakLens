# LeakLens

**Inspect before you expose.**

LeakLens is a local-first workbench for finding and redacting sensitive text
before you share it. Paste text or import a small file, read what the rules
find, select what to redact, and copy or download the sanitized result.

It runs entirely in your browser tab. There is no server, no build step, and
no dependency: open `index.html` and it works.

> **What "no findings" means:** the rules found no matches. It does **not**
> mean your text contains nothing sensitive. LeakLens looks for common shapes;
> it cannot know your context and it does not catch everything. Always read
> the text yourself before sharing it.

---

## How to run it

1. Download or clone this folder.
2. Open `index.html` in any modern browser (Chrome, Edge, Firefox, Safari).
3. Paste text (or click **Import file…**), press **Scan text**, and work the
   findings list.

Optional: run the logic test suite with Node.js (18+, for the `d` regex flag):

```bash
node tests.js
```

No other tooling is used or required.

## What it detects

Eleven rules across four categories, each documented in the app's
**How the rules work** section — that section is generated from the same rule
registry the scanner runs, so the page always describes what the tool
actually does.

| Category | Rules |
| --- | --- |
| Credentials | `api-key-assignment`, `access-token-assignment`, `password-assignment`, `bearer-token`, `jwt-like-token`, `cloud-access-key-id`, `private-key-block`, `database-uri-credentials` |
| Personal data | `email-address`, `phone-like-value` |
| Infrastructure | `ipv4-address` |

### Severity labels

- **Critical** — private-key blocks. If genuine, this is the most sensitive
  material here; treat it as compromised and rotate it, don't just delete it.
- **High** — credential-bearing values (API keys, tokens, passwords,
  connection strings). Structure suggests a secret; validity is never tested.
- **Review** — personal data (emails, phones) and infrastructure (IP
  addresses), plus matches that look like placeholders. These are often not
  secrets, but they deserve a human look.

LeakLens never computes a numeric score. Labels are advisory, not a verdict.

### Deliberate limits

- The scanner matches **shapes, not meaning**. It will miss secrets it has no
  rule for, and it will flag things that are not secrets.
- Placeholder-looking values (`YOUR_API_KEY_HERE`, `CHANGEME`, …) are still
  reported but downgraded to **Review**, so they are never silently dropped.
- An unterminated private-key header is bounded to its header line plus one
  body line — never scanned to end-of-file.
- Known documentation examples (e.g. AWS's `AKIAIOSFODNN7EXAMPLE`) are
  downgraded to Review.
- The scanner performs **no network validation** of any finding — ever.
  Nothing is checked against any provider, service, or API.

## How redaction works

- Findings are **zero-based UTF-16 offsets** into the exact string that was
  scanned (`start` inclusive, `end` exclusive), aligned with
  `String.prototype.slice`.
- Redaction is a pure function: it rebuilds the output from untouched slices
  and never mutates the source.
- Selected ranges that overlap are union-merged; the placeholder of the
  longest span in each merged group is used (e.g. a Bearer header that is
  also a JWT becomes one `[REDACTED_BEARER_TOKEN]`).
- Placeholders are fixed, self-describing strings such as
  `[REDACTED_API_KEY]` — the original value is replaced, never stored.
- Previews are **masked** (head characters plus bullets) and capped in
  length; a full raw value is never rendered, logged, or copied to any
  attribute.
- Editing the text after a scan marks the results **stale**: the sanitized
  preview still reflects the scanned version, the UI says so, and re-scanning
  refreshes everything.
- Dismissing a false positive keeps it visible but greyed for the current tab
  session and excludes it from redaction. Dismissals are never persisted;
  closing the tab forgets them.

## Privacy model

LeakLens is built so it **cannot** send your text anywhere:

- No `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, or analytics.
- No `localStorage`, `sessionStorage`, IndexedDB, or cookies. Nothing is
  persisted by default.
- No external scripts, fonts, CDNs, or remote assets.
- No secrets in URLs, query strings, or browser history.
- Untrusted text reaches the DOM only through `textContent` / DOM APIs — no
  HTML injection of scanned content.
- Download links use temporary object URLs that are revoked after use.
- The input and matched values are never logged to the console.

The `samples.js` fixtures are deliberately fictional: IETF-reserved example
domains (`example.test`), RFC 5737 documentation addresses (`192.0.2.x`), and
credential strings that spell out that they are not real. Never paste real
credentials into a web page — this one included.

## File import & export

- Import accepts `.txt .log .json .env .yaml .yml .toml .ini .conf`, with a
  size check before reading (limit: 250,000 characters).
- Export produces a plain `.txt` download of the sanitized preview only.
- Copying uses the async Clipboard API where available, with a
  `execCommand('copy')` fallback for non-secure contexts, and reports failure
  honestly rather than claiming success.

## Testing

`tests.js` is a zero-dependency Node harness (no test framework) covering the
detection and redaction engine: exact offsets, LF/CRLF/CR line numbering,
overlap merging, invalid-range refusal, determinism, adversarial-length
inputs, and the documented placeholder/boundary policies. Run:

```bash
node tests.js
```

72 assertions, exit code `1` on any failure.

## Limitations & honest disclosures

- **Rules, not understanding.** A fixed regex set cannot reason about your
  content. Expect both false negatives and false positives.
- **No safety verdict.** "No matches" is a statement about eleven rules, not
  about your data.
- **UTF-16 columns are approximate** around emoji and other multi-unit
  characters; line numbers are exact for LF, CRLF, and CR text.
- **Phone detection is heuristic** and label-gated; timestamps and IDs may
  overlap its shape.
- **Email matching is practical, not RFC 5322-complete.**
- **The scanner is English-biased** in its labels and heuristics.
- Tested in Chromium; other modern browsers should behave the same, but
  clipboard behavior varies by browser and permission policy.

## License

MIT — see [LICENSE](LICENSE).
