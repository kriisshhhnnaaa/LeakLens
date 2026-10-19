/*
 * LeakLens — script.js
 *
 * UI layer. Talks only to the pure engine in detector.js.
 *
 * Privacy posture (enforced here by construction):
 *  - no fetch / XMLHttpRequest / WebSocket / sendBeacon anywhere
 *  - no localStorage / sessionStorage / IndexedDB / cookies
 *  - no console logging of source text, findings, or raw values
 *  - untrusted text reaches the DOM only through textContent
 *  - download object URLs are revoked after use
 *
 * State model:
 *  - editorText     what is in the textarea right now
 *  - snapshot       the exact string that was scanned (frozen at scan time)
 *  - scanResult     the engine result for snapshot
 *  - stale          true when editorText !== snapshot
 * Redactions always apply to snapshot. If the editor has changed since
 * the scan, the UI says so and offers a re-scan.
 */
(function () {
  'use strict';

  var D = window.LeakLensDetector;
  var SAMPLES = window.LeakLensSamples || [];
  var MAX_LEN = D.LIMITS.MAX_SOURCE_LEN;

  /* ---------- element handles ---------- */
  var $ = function (id) { return document.getElementById(id); };

  var el = {
    textarea: $('source-text'),
    charCount: $('char-count'),
    wordCount: $('word-count'),
    sizeWarning: $('doc-size-warning'),
    scan: $('btn-scan'),
    clear: $('btn-clear'),
    importBtn: $('btn-import'),
    fileInput: $('file-input'),
    samplesList: $('samples-list'),
    ledgerSub: $('ledger-sub'),
    ledgerEmpty: $('ledger-empty'),
    findingsList: $('findings-list'),
    ledgerTools: $('ledger-tools'),
    selectAll: $('btn-select-all'),
    selectNone: $('btn-select-none'),
    restoreDismissed: $('btn-restore-dismissed'),
    redactBox: $('redact-box'),
    redactNote: $('redact-note'),
    redactPreview: $('redact-preview'),
    copyBtn: $('btn-copy'),
    downloadBtn: $('btn-download'),
    copyFeedback: $('copy-feedback'),
    scanError: $('scan-error'),
    methodologyList: $('methodology-list'),
    announcer: $('announcer')
  };

  /* ---------- state ---------- */
  var editorText = '';
  var snapshot = null;      // exact string scanned
  var scanResult = null;    // engine result for snapshot
  var selectedIds = {};     // finding.id -> true
  var dismissedIds = {};    // finding.id -> true (session only)
  var downloadUrl = null;   // revoked after each download

  /* ---------- tiny helpers (safe DOM only) ---------- */
  function clearNode(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function setText(node, text) {
    clearNode(node);
    node.appendChild(document.createTextNode(text));
  }

  function announce(text) {
    setText(el.announcer, text);
  }

  function countWords(text) {
    var m = text.match(/\S+/g);
    return m ? m.length : 0;
  }

  /* ============================================================
   * Methodology — generated from the rule registry, so the page
   * always describes what the scanner actually does.
   * ============================================================ */
  function buildMethodology() {
    clearNode(el.methodologyList);
    D.RULES.forEach(function (rule) {
      var card = document.createElement('article');
      card.className = 'rule-card';

      var head = document.createElement('div');
      head.className = 'rule-card-head';

      var h = document.createElement('h3');
      setText(h, rule.title);
      head.appendChild(h);

      var id = document.createElement('span');
      id.className = 'rule-card-id';
      setText(id, rule.id);
      head.appendChild(id);

      var cat = document.createElement('span');
      cat.className = 'rule-card-cat';
      setText(cat, rule.category + ' · ' + rule.severity);
      head.appendChild(cat);

      card.appendChild(head);

      var p = document.createElement('p');
      setText(p, rule.explanation);
      card.appendChild(p);

      el.methodologyList.appendChild(card);
    });
  }

  /* ============================================================
   * Counts and size limit
   * ============================================================ */
  function updateCounts() {
    editorText = el.textarea.value;
    setText(el.charCount, editorText.length.toLocaleString() + ' characters');
    setText(el.wordCount, countWords(editorText).toLocaleString() + ' words');
    var over = editorText.length > MAX_LEN;
    el.sizeWarning.hidden = !over;
    el.scan.disabled = over;
    if (snapshot !== null) {
      markStaleState(editorText !== snapshot);
    }
  }

  function markStaleState(isStale) {
    if (isStale && scanResult && !el.redactBox.hidden) {
      el.redactNote.textContent = '';
      el.redactNote.appendChild(document.createTextNode(
        'The text has changed since this scan. The preview below reflects the ' +
        'scanned version, not the current editor text. Re-scan to refresh.'
      ));
      el.redactBox.classList.add('is-stale');
    } else if (scanResult && !el.redactBox.hidden) {
      refreshRedactNote();
      el.redactBox.classList.remove('is-stale');
    }
  }

  /* ============================================================
   * Samples
   * ============================================================ */
  function buildSamples() {
    clearNode(el.samplesList);
    SAMPLES.forEach(function (s) {
      var li = document.createElement('li');
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'sample-btn';
      btn.textContent = s.name;
      btn.setAttribute('aria-label', 'Load sample: ' + s.name);
      btn.addEventListener('click', function () {
        loadSample(s);
      });
      li.appendChild(btn);
      el.samplesList.appendChild(li);
    });
  }

  function loadSample(sample) {
    // Validate the fixture through the real engine before loading it, so
    // a broken sample can never silently present wrong expectations.
    var result = D.scanText(sample.text);
    var ok = checkExpectations(sample, result);
    if (!ok) {
      showScanError('This built-in sample did not pass its own self-check. ' +
        'Nothing was loaded — the fixture may be broken.');
      return;
    }
    hideScanError();
    el.textarea.value = sample.text;
    updateCounts();
    runScan();
  }

  function checkExpectations(sample, result) {
    var exp = sample.expect || {};
    var ok = true;
    if (exp.none) {
      ok = result.findings.length === 0;
    }
    if (exp.contains) {
      exp.contains.forEach(function (c) {
        var n = result.findings.filter(function (f) {
          return (f.ruleIds || []).indexOf(c.ruleId) !== -1 || f.ruleId === c.ruleId;
        }).length;
        if (n < (c.min || 1)) ok = false;
      });
    }
    if (exp.severities) {
      var sev = result.findings.map(function (f) { return f.severity; });
      exp.severities.forEach(function (s) {
        if (sev.indexOf(s) === -1) ok = false;
      });
    }
    return ok;
  }

  /* ============================================================
   * File import
   * ============================================================ */
  function importFile(file) {
    if (!file) return;
    // Size gate before reading anything.
    if (file.size > MAX_LEN * 4) {
      showScanError('That file is too large to inspect here (' +
        Math.round(file.size / 1024) + ' KB). Keep files under roughly 1 MB of text.');
      return;
    }
    var reader = new FileReader();
    reader.onload = function () {
      var text = String(reader.result || '');
      if (text.length > MAX_LEN) {
        showScanError('That file holds ' + text.length.toLocaleString() +
          ' characters — over the ' + MAX_LEN.toLocaleString() + ' limit. Trim or split it first.');
        return;
      }
      hideScanError();
      el.textarea.value = text;
      updateCounts();
      runScan();
    };
    reader.onerror = function () {
      showScanError('The file could not be read. It may be unreadable or still moving.');
    };
    reader.readAsText(file);
  }

  /* ============================================================
   * Scanning
   * ============================================================ */
  function runScan() {
    editorText = el.textarea.value;
    if (editorText.length > MAX_LEN) {
      showScanError('Text is over the ' + MAX_LEN.toLocaleString() +
        ' character limit. Trim or split it before scanning.');
      return;
    }
    hideScanError();

    var result;
    try {
      result = D.scanText(editorText);
    } catch (err) {
      showScanError('The scanner hit an unexpected error and stopped. ' +
        'No results are shown, because a partial result could mislead.');
      return;
    }

    if (!result.complete) {
      showScanError('The scan did not complete (' + (result.error || 'unknown reason') +
        '). No results are shown.');
      return;
    }

    // Freeze the scanned snapshot.
    snapshot = editorText;
    scanResult = result;
    selectedIds = {};
    dismissedIds = {};
    renderFindings();
    renderRedact();

    var c = result.counts;
    var parts = [];
    if (c.critical) parts.push(c.critical + ' critical');
    if (c.high) parts.push(c.high + ' high');
    if (c.review) parts.push(c.review + ' review');
    var summary = result.findings.length === 0
      ? 'Scan complete: no matches from the current rules. That is not proof the text is safe — read it yourself.'
      : 'Scan complete: ' + result.findings.length + ' finding' +
        (result.findings.length === 1 ? '' : 's') +
        (parts.length ? ' (' + parts.join(', ') + ')' : '') + '.';
    setText(el.ledgerSub, result.findings.length === 0
      ? 'No matches — not a safety guarantee.'
      : result.findings.length + ' finding' + (result.findings.length === 1 ? '' : 's'));
    announce(summary);
  }

  function showScanError(msg) {
    setText(el.scanError, msg);
    el.scanError.hidden = false;
    announce(msg);
  }

  function hideScanError() {
    el.scanError.hidden = true;
    setText(el.scanError, '');
  }

  /* ============================================================
   * Findings ledger
   * ============================================================ */
  function visibleFindings() {
    if (!scanResult) return [];
    return scanResult.findings.filter(function (f) { return !dismissedIds[f.id]; });
  }

  function renderFindings() {
    clearNode(el.findingsList);
    var findings = scanResult ? scanResult.findings : [];
    var anyDismissed = findings.some(function (f) { return dismissedIds[f.id]; });

    el.ledgerEmpty.hidden = findings.length > 0;
    el.ledgerTools.hidden = findings.length === 0;
    el.restoreDismissed.hidden = !anyDismissed;

    if (findings.length === 0) {
      if (scanResult) {
        // Scan ran; genuinely no matches. State the limitation, loudly.
        clearNode(el.ledgerEmpty);
        var p1 = document.createElement('p');
        setText(p1, 'No matches from the current rules.');
        var p2 = document.createElement('p');
        p2.className = 'ledger-empty-hint';
        setText(p2, 'The rules look for common shapes only. This does not mean the text ' +
          'contains nothing sensitive — read it yourself before sharing.');
        el.ledgerEmpty.appendChild(p1);
        el.ledgerEmpty.appendChild(p2);
      }
      return;
    }

    var sevRank = { critical: 0, high: 1, review: 2 };
    findings.slice().sort(function (a, b) {
      if (sevRank[a.severity] !== sevRank[b.severity]) return sevRank[a.severity] - sevRank[b.severity];
      return a.start - b.start;
    }).forEach(function (f) {
      el.findingsList.appendChild(buildFindingRow(f));
    });
  }

  function buildFindingRow(f) {
    var li = document.createElement('li');
    li.className = 'finding';
    li.setAttribute('data-severity', f.severity);
    li.setAttribute('data-finding-id', f.id);
    if (selectedIds[f.id]) li.classList.add('selected');
    if (dismissedIds[f.id]) li.classList.add('dismissed');

    var top = document.createElement('div');
    top.className = 'finding-top';

    // Checkbox: the label wraps everything clickable.
    var cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.className = 'finding-checkbox';
    cb.id = 'cb-' + f.id;
    cb.checked = !!selectedIds[f.id];
    cb.disabled = !!dismissedIds[f.id];
    cb.addEventListener('change', function () {
      if (cb.checked) selectedIds[f.id] = true;
      else delete selectedIds[f.id];
      li.classList.toggle('selected', cb.checked);
      renderRedact();
    });

    var label = document.createElement('label');
    label.className = 'finding-label';
    label.setAttribute('for', cb.id);

    var sev = document.createElement('span');
    sev.className = 'finding-severity';
    setText(sev, f.severity);
    label.appendChild(sev);

    var rule = document.createElement('span');
    rule.className = 'finding-rule';
    setText(rule, f.title);
    label.appendChild(rule);

    var ref = document.createElement('span');
    ref.className = 'finding-ref';
    setText(ref, 'L' + f.line + ' · C' + f.column);
    label.appendChild(ref);

    top.appendChild(cb);
    top.appendChild(label);
    li.appendChild(top);

    // Masked preview only — never the raw value.
    var prev = document.createElement('div');
    prev.className = 'finding-preview';
    setText(prev, f.maskedPreview);
    li.appendChild(prev);

    if (f.note) {
      var note = document.createElement('div');
      note.className = 'finding-note';
      setText(note, f.note);
      li.appendChild(note);
    }

    var explain = document.createElement('div');
    explain.className = 'finding-explain';
    setText(explain, f.explanation);
    li.appendChild(explain);

    var actions = document.createElement('div');
    actions.className = 'finding-actions';
    var dis = document.createElement('button');
    dis.type = 'button';
    dis.className = 'finding-dismiss dismiss-btn';
    setText(dis, 'Dismiss (false positive)');
    dis.addEventListener('click', function () {
      dismissedIds[f.id] = true;
      li.classList.add('dismissed');
      cb.disabled = true;
      cb.checked = false;
      delete selectedIds[f.id];
      li.classList.remove('selected');
      renderFindings();
      renderRedact();
    });
    actions.appendChild(dis);

    var res = document.createElement('button');
    res.type = 'button';
    res.className = 'finding-dismiss restore-btn';
    setText(res, 'Restore');
    res.addEventListener('click', function () {
      delete dismissedIds[f.id];
      renderFindings();
    });
    actions.appendChild(res);

    li.appendChild(actions);
    return li;
  }

  /* ============================================================
   * Redaction preview + export
   * ============================================================ */
  function selectedFindings() {
    if (!scanResult) return [];
    return scanResult.findings.filter(function (f) { return selectedIds[f.id]; });
  }

  function refreshRedactNote() {
    var sel = selectedFindings();
    if (sel.length === 0) {
      setText(el.redactNote, 'Nothing selected. Tick findings above to replace them with placeholders.');
    } else {
      setText(el.redactNote, sel.length + ' selected — each becomes its placeholder in the preview.');
    }
  }

  function renderRedact() {
    var hasResult = !!scanResult;
    el.redactBox.hidden = !hasResult;
    if (!hasResult) return;

    refreshRedactNote();
    var sel = selectedFindings();
    var output;
    try {
      output = D.redact(snapshot, sel, scanResult);
    } catch (err) {
      // Invalid or mismatched state: refuse to show anything rather than
      // show text that looks sanitized but is not.
      setText(el.redactPreview, '');
      setText(el.redactNote, 'The redaction could not be produced for the current selection. Re-scan and select again.');
      return;
    }
    setText(el.redactPreview, output);
  }

  function copySanitized() {
    if (!scanResult) return;
    var sel = selectedFindings();
    var output;
    try {
      output = D.redact(snapshot, sel, scanResult);
    } catch (err) {
      setCopyFeedback('Copy failed — re-scan first.');
      return;
    }
    var done = function () { setCopyFeedback('Copied ' + output.length.toLocaleString() + ' characters.'); };
    var fail = function () { setCopyFeedback('Copy was blocked by the browser. Use Download instead.'); };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(output).then(done, function () {
        legacyCopy(output) ? done() : fail();
      });
    } else {
      legacyCopy(output) ? done() : fail();
    }
  }

  function legacyCopy(text) {
    // Fallback for non-secure contexts: a temporary textarea + execCommand.
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    return ok;
  }

  function setCopyFeedback(msg) {
    setText(el.copyFeedback, msg);
    announce(msg);
    window.setTimeout(function () {
      setText(el.copyFeedback, '');
    }, 4000);
  }

  function downloadSanitized() {
    if (!scanResult) return;
    var sel = selectedFindings();
    var output;
    try {
      output = D.redact(snapshot, sel, scanResult);
    } catch (err) {
      setCopyFeedback('Download failed — re-scan first.');
      return;
    }
    var blob = new Blob([output], { type: 'text/plain;charset=utf-8' });
    if (downloadUrl) {
      window.URL.revokeObjectURL(downloadUrl);
      downloadUrl = null;
    }
    downloadUrl = window.URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = downloadUrl;
    a.download = 'leaklens-sanitized.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    // Revoke on the next tick so the download has started.
    window.setTimeout(function () {
      if (downloadUrl) {
        window.URL.revokeObjectURL(downloadUrl);
        downloadUrl = null;
      }
    }, 1000);
    announce('Download started.');
  }

  /* ============================================================
   * Clear
   * ============================================================ */
  function clearAll() {
    el.textarea.value = '';
    editorText = '';
    snapshot = null;
    scanResult = null;
    selectedIds = {};
    dismissedIds = {};
    hideScanError();
    renderFindings();
    renderRedact();
    updateCounts();
    el.textarea.focus();
    announce('Cleared. Nothing is kept from the previous text.');
  }

  /* ============================================================
   * Wire-up
   * ============================================================ */
  function init() {
    buildMethodology();
    buildSamples();

    el.textarea.addEventListener('input', updateCounts);
    el.scan.addEventListener('click', runScan);
    el.clear.addEventListener('click', clearAll);
    el.importBtn.addEventListener('click', function () { el.fileInput.click(); });
    el.fileInput.addEventListener('change', function () {
      if (el.fileInput.files && el.fileInput.files[0]) {
        importFile(el.fileInput.files[0]);
      }
      el.fileInput.value = '';
    });
    el.selectAll.addEventListener('click', function () {
      visibleFindings().forEach(function (f) { selectedIds[f.id] = true; });
      renderFindings();
      renderRedact();
    });
    el.selectNone.addEventListener('click', function () {
      selectedIds = {};
      renderFindings();
      renderRedact();
    });
    el.restoreDismissed.addEventListener('click', function () {
      dismissedIds = {};
      renderFindings();
      renderRedact();
    });
    el.copyBtn.addEventListener('click', copySanitized);
    el.downloadBtn.addEventListener('click', downloadSanitized);

    window.addEventListener('pagehide', function () {
      if (downloadUrl) {
        window.URL.revokeObjectURL(downloadUrl);
        downloadUrl = null;
      }
    });

    updateCounts();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
