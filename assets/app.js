(function (global) {
  "use strict";

  var LEAK_TYPE_CONFIG = {
    definitely: {
      label: "Definitely lost",
      severity: "critical",
      impact: "Memoria perdida sem nenhuma referencia valida."
    },
    indirectly: {
      label: "Indirectly lost",
      severity: "warning",
      impact: "Memoria anexada a outro bloco definitivamente perdido."
    },
    possibly: {
      label: "Possibly lost",
      severity: "warning",
      impact: "Ha ponteiro parcial ou ambiguidade no ownership."
    },
    reachable: {
      label: "Still reachable",
      severity: "info",
      impact: "Memoria ainda referenciada no encerramento do processo."
    },
    suppressed: {
      label: "Suppressed",
      severity: "info",
      impact: "Ocorrencia escondida por regra de suppressions."
    }
  };

  var ERROR_HEADER_PATTERNS = [
    /^Invalid read of size /i,
    /^Invalid write of size /i,
    /^Use of uninitialised value/i,
    /^Conditional jump or move depends on uninitialised value/i,
    /^Syscall param .* points to uninitialised byte/i,
    /^Invalid free/i,
    /^Mismatched free/i,
    /^Source and destination overlap/i,
    /^Jump to the invalid address/i,
    /^Fishy value/i
  ];

  var state = createEmptyState();
  var refs = null;
  var appInitialized = false;

  function createEmptyState() {
    return {
      rawText: "",
      inputLabel: "",
      source: "unknown",
      metadata: {},
      heapSummary: null,
      leakSummary: [],
      leakRecords: [],
      errorSummary: null,
      errorRecords: [],
      diagnostics: [],
      totalLines: 0
    };
  }

  function splitLines(text) {
    return String(text || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  }

  function stripValgrindPrefix(line) {
    return String(line || "").replace(/^==\d+==\s?/, "");
  }

  function normalizeNumber(value) {
    if (value === null || value === undefined || value === "") {
      return 0;
    }
    return Number(String(value).replace(/[^\d]/g, "")) || 0;
  }

  function formatCount(value) {
    return normalizeNumber(value).toLocaleString("pt-BR");
  }

  function formatBytes(value) {
    var bytes = normalizeNumber(value);
    if (!bytes) {
      return "0 B";
    }

    var units = ["B", "KB", "MB", "GB", "TB"];
    var index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    var scaled = bytes / Math.pow(1024, index);
    var digits = scaled >= 100 || index === 0 ? 0 : scaled >= 10 ? 1 : 2;
    return scaled.toLocaleString("pt-BR", {
      minimumFractionDigits: digits,
      maximumFractionDigits: digits
    }) + " " + units[index];
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function highlightText(text, query) {
    var source = String(text || "");
    if (!query) {
      return escapeHtml(source);
    }

    var lower = source.toLowerCase();
    var needle = query.toLowerCase();
    var cursor = 0;
    var output = "";

    while (cursor < source.length) {
      var matchIndex = lower.indexOf(needle, cursor);
      if (matchIndex === -1) {
        output += escapeHtml(source.slice(cursor));
        break;
      }

      output += escapeHtml(source.slice(cursor, matchIndex));
      output += "<mark>" + escapeHtml(source.slice(matchIndex, matchIndex + needle.length)) + "</mark>";
      cursor = matchIndex + needle.length;
    }

    return output;
  }

  function detectSource(text) {
    if (/AddressSanitizer|LeakSanitizer/i.test(text)) {
      return "asan";
    }
    if (/Memcheck|HEAP SUMMARY:|LEAK SUMMARY:|ERROR SUMMARY:/i.test(text)) {
      return "valgrind";
    }
    return "valgrind";
  }

  function createAnalyzerState(text, inputLabel) {
    var rawText = String(text || "");
    var source = detectSource(rawText);
    var parsed = source === "asan" ? parseAsan(rawText) : parseValgrind(rawText);

    return {
      rawText: rawText,
      inputLabel: inputLabel || "Log carregado",
      source: source,
      metadata: parsed.metadata,
      heapSummary: parsed.heapSummary,
      leakSummary: parsed.leakSummary,
      leakRecords: parsed.leakRecords,
      errorSummary: parsed.errorSummary,
      errorRecords: parsed.errorRecords,
      diagnostics: parsed.diagnostics,
      totalLines: splitLines(rawText).length
    };
  }

  function parseValgrind(text) {
    var lines = splitLines(text);
    var cleanLines = lines.map(stripValgrindPrefix);
    var metadata = parseValgrindMetadata(text, cleanLines);
    var heapSummary = parseValgrindHeap(text);
    var leakSummary = parseValgrindLeakSummary(text);
    var leakRecords = parseValgrindLeakRecords(cleanLines);
    var errorSummary = parseValgrindErrorSummary(text);
    var errorRecords = parseValgrindErrorRecords(cleanLines);
    var diagnostics = buildValgrindDiagnostics({
      heapSummary: heapSummary,
      leakSummary: leakSummary,
      leakRecords: leakRecords,
      errorSummary: errorSummary,
      errorRecords: errorRecords
    });

    return {
      metadata: metadata,
      heapSummary: heapSummary,
      leakSummary: leakSummary,
      leakRecords: leakRecords,
      errorSummary: errorSummary,
      errorRecords: errorRecords,
      diagnostics: diagnostics
    };
  }

  function parseValgrindMetadata(text, cleanLines) {
    var pidMatch = text.match(/^==(\d+)==/m);
    var commandMatch = text.match(/Command:\s*(.+)/);
    var parentPidMatch = text.match(/Parent PID:\s*(\d+)/i);
    var toolLine = cleanLines.find(function (line) {
      return /Memcheck, a memory error detector/i.test(line);
    }) || "";
    var versionMatch = text.match(/Using\s+(Valgrind-[^ ]+)/i);

    return {
      tool: toolLine || "Memcheck",
      version: versionMatch ? versionMatch[1] : "",
      pid: pidMatch ? pidMatch[1] : "",
      parentPid: parentPidMatch ? parentPidMatch[1] : "",
      command: commandMatch ? commandMatch[1].trim() : ""
    };
  }

  function parseValgrindHeap(text) {
    var inUseMatch = text.match(/in use at exit:\s+([\d,]+) bytes in ([\d,]+) blocks/i);
    var totalMatch = text.match(/total heap usage:\s+([\d,]+) allocs,\s+([\d,]+) frees,\s+([\d,]+) bytes allocated/i);

    if (!inUseMatch && !totalMatch) {
      return null;
    }

    return {
      inUseBytes: inUseMatch ? normalizeNumber(inUseMatch[1]) : 0,
      inUseBlocks: inUseMatch ? normalizeNumber(inUseMatch[2]) : 0,
      allocs: totalMatch ? normalizeNumber(totalMatch[1]) : 0,
      frees: totalMatch ? normalizeNumber(totalMatch[2]) : 0,
      totalAllocated: totalMatch ? normalizeNumber(totalMatch[3]) : 0
    };
  }

  function parseValgrindLeakSummary(text) {
    return Object.keys(LEAK_TYPE_CONFIG).map(function (key) {
      var regex;
      if (key === "suppressed") {
        regex = /suppressed:\s+([\d,]+) bytes in ([\d,]+) blocks/i;
      } else if (key === "definitely") {
        regex = /definitely lost:\s+([\d,]+) bytes in ([\d,]+) blocks/i;
      } else if (key === "indirectly") {
        regex = /indirectly lost:\s+([\d,]+) bytes in ([\d,]+) blocks/i;
      } else if (key === "possibly") {
        regex = /possibly lost:\s+([\d,]+) bytes in ([\d,]+) blocks/i;
      } else {
        regex = /still reachable:\s+([\d,]+) bytes in ([\d,]+) blocks/i;
      }

      var match = text.match(regex);
      return {
        leakType: key,
        label: LEAK_TYPE_CONFIG[key].label,
        severity: LEAK_TYPE_CONFIG[key].severity,
        impact: LEAK_TYPE_CONFIG[key].impact,
        bytes: match ? normalizeNumber(match[1]) : 0,
        blocks: match ? normalizeNumber(match[2]) : 0
      };
    });
  }

  function parseValgrindErrorSummary(text) {
    var match = text.match(/ERROR SUMMARY:\s+([\d,]+) errors? from ([\d,]+) contexts?(?: \(suppressed:\s*([\d,]+) from ([\d,]+)\))?/i);
    if (!match) {
      return null;
    }

    return {
      errors: normalizeNumber(match[1]),
      contexts: normalizeNumber(match[2]),
      suppressedErrors: normalizeNumber(match[3]),
      suppressedContexts: normalizeNumber(match[4])
    };
  }

  function parseValgrindLeakRecords(cleanLines) {
    var records = [];
    var current = null;
    var leakHeaderPattern = /^([\d,]+) bytes in ([\d,]+) blocks? (?:are|is) (definitely lost|indirectly lost|possibly lost|still reachable)(?: in loss record (\d+) of (\d+))?/i;

    function finishCurrent() {
      if (!current) {
        return;
      }
      while (current.rawBlock.length && current.rawBlock[current.rawBlock.length - 1] === "") {
        current.rawBlock.pop();
      }
      current.id = current.recordIndex && current.recordTotal ? current.recordIndex + "/" + current.recordTotal : String(records.length + 1);
      current.firstFrame = current.frames[0] || current.notes[0] || "";
      records.push(current);
      current = null;
    }

    cleanLines.forEach(function (line) {
      var raw = String(line || "").replace(/\s+$/, "");
      var plain = raw.trim();
      var headerMatch = plain.match(leakHeaderPattern);

      if (headerMatch) {
        finishCurrent();
        current = {
          bytes: normalizeNumber(headerMatch[1]),
          blocks: normalizeNumber(headerMatch[2]),
          leakType: mapLeakType(headerMatch[3]),
          recordIndex: headerMatch[4] ? normalizeNumber(headerMatch[4]) : 0,
          recordTotal: headerMatch[5] ? normalizeNumber(headerMatch[5]) : 0,
          frames: [],
          notes: [],
          rawBlock: [raw]
        };
        return;
      }

      if (!current) {
        return;
      }

      if (!plain) {
        current.rawBlock.push("");
        return;
      }

      if (isValgrindSectionHeader(plain) || isValgrindErrorHeader(plain)) {
        finishCurrent();
        return;
      }

      current.rawBlock.push(raw);
      if (isValgrindFrame(plain)) {
        current.frames.push(plain);
      } else {
        current.notes.push(plain);
      }
    });

    finishCurrent();
    return records;
  }

  function mapLeakType(text) {
    var normalized = String(text || "").toLowerCase();
    if (normalized.indexOf("definitely") >= 0) {
      return "definitely";
    }
    if (normalized.indexOf("indirectly") >= 0) {
      return "indirectly";
    }
    if (normalized.indexOf("possibly") >= 0) {
      return "possibly";
    }
    return "reachable";
  }

  function isValgrindFrame(text) {
    return /^(at|by)\s+0x[0-9a-f]+:/i.test(text);
  }

  function isValgrindSectionHeader(text) {
    return /^(HEAP SUMMARY:|LEAK SUMMARY:|ERROR SUMMARY:|For lists of detected and suppressed errors|All heap blocks were freed)/i.test(text);
  }

  function isValgrindErrorHeader(text) {
    return ERROR_HEADER_PATTERNS.some(function (pattern) {
      return pattern.test(text);
    });
  }

  function parseValgrindErrorRecords(cleanLines) {
    var records = [];
    var current = null;

    function finishCurrent() {
      if (!current) {
        return;
      }
      while (current.rawBlock.length && current.rawBlock[current.rawBlock.length - 1] === "") {
        current.rawBlock.pop();
      }
      current.id = String(records.length + 1);
      current.firstFrame = current.frames[0] || current.notes[0] || "";
      records.push(current);
      current = null;
    }

    cleanLines.forEach(function (line) {
      var raw = String(line || "").replace(/\s+$/, "");
      var plain = raw.trim();

      if (isValgrindErrorHeader(plain)) {
        finishCurrent();
        current = {
          type: plain,
          severity: classifyValgrindError(plain),
          frames: [],
          notes: [],
          rawBlock: [raw]
        };
        return;
      }

      if (!current) {
        return;
      }

      if (!plain) {
        current.rawBlock.push("");
        return;
      }

      if (isValgrindSectionHeader(plain) || /^([\d,]+) bytes in ([\d,]+) blocks?/i.test(plain)) {
        finishCurrent();
        return;
      }

      current.rawBlock.push(raw);
      if (isValgrindFrame(plain)) {
        current.frames.push(plain);
      } else {
        current.notes.push(plain);
      }
    });

    finishCurrent();
    return records;
  }

  function classifyValgrindError(type) {
    if (/Invalid read|Invalid write|Invalid free|Mismatched free|Jump to the invalid address/i.test(type)) {
      return "critical";
    }
    if (/Use of uninitialised|Conditional jump|Syscall param/i.test(type)) {
      return "high";
    }
    if (/Fishy value|overlap/i.test(type)) {
      return "warning";
    }
    return "info";
  }

  function buildValgrindDiagnostics(parsed) {
    var diagnostics = [];
    var summaryLeakBytes = parsed.leakSummary
      .filter(function (entry) { return entry.leakType !== "suppressed"; })
      .reduce(function (sum, entry) { return sum + normalizeNumber(entry.bytes); }, 0);
    var summaryLeakBlocks = parsed.leakSummary
      .filter(function (entry) { return entry.leakType !== "suppressed"; })
      .reduce(function (sum, entry) { return sum + normalizeNumber(entry.blocks); }, 0);
    var recordLeakBytes = parsed.leakRecords.reduce(function (sum, entry) { return sum + normalizeNumber(entry.bytes); }, 0);
    var recordLeakBlocks = parsed.leakRecords.reduce(function (sum, entry) { return sum + normalizeNumber(entry.blocks); }, 0);

    if (summaryLeakBytes > 0 && parsed.leakRecords.length === 0) {
      diagnostics.push({
        level: "warn",
        message: "O leak summary indica memoria pendente, mas nenhum loss record individual foi capturado."
      });
    } else if (summaryLeakBytes === recordLeakBytes && summaryLeakBlocks === recordLeakBlocks) {
      diagnostics.push({
        level: "ok",
        message: "Os totais do leak summary batem com os loss records individuais encontrados pelo parser."
      });
    } else if (summaryLeakBytes || recordLeakBytes || summaryLeakBlocks || recordLeakBlocks) {
      diagnostics.push({
        level: "warn",
        message: "Ha diferenca entre o leak summary e os loss records individuais: summary " +
          formatBytes(summaryLeakBytes) + " em " + formatCount(summaryLeakBlocks) +
          " blocos, records " + formatBytes(recordLeakBytes) + " em " + formatCount(recordLeakBlocks) + " blocos."
      });
    }

    if (parsed.errorSummary && parsed.errorRecords.length && parsed.errorSummary.contexts !== parsed.errorRecords.length) {
      diagnostics.push({
        level: "warn",
        message: "O ERROR SUMMARY reporta " + formatCount(parsed.errorSummary.contexts) +
          " contextos, mas o parser encontrou " + formatCount(parsed.errorRecords.length) + " blocos detalhados."
      });
    } else if (parsed.errorSummary) {
      diagnostics.push({
        level: "ok",
        message: "ERROR SUMMARY lido com " + formatCount(parsed.errorSummary.errors) +
          " erros em " + formatCount(parsed.errorSummary.contexts) + " contextos."
      });
    }

    if (!diagnostics.length) {
      diagnostics.push({
        level: "ok",
        message: "Nenhuma inconsistencia detectada entre os blocos parseados."
      });
    }

    return diagnostics;
  }

  function parseAsan(text) {
    var lines = splitLines(text);
    var leakRecords = [];
    var errorRecords = [];
    var current = null;
    var currentKind = "";

    function finishCurrent() {
      if (!current) {
        return;
      }
      while (current.rawBlock.length && current.rawBlock[current.rawBlock.length - 1] === "") {
        current.rawBlock.pop();
      }
      current.firstFrame = current.frames[0] || current.notes[0] || "";
      if (currentKind === "leak") {
        current.id = String(leakRecords.length + 1);
        leakRecords.push(current);
      } else {
        current.id = String(errorRecords.length + 1);
        errorRecords.push(current);
      }
      current = null;
      currentKind = "";
    }

    lines.forEach(function (line) {
      var raw = String(line || "").replace(/\s+$/, "");
      var plain = raw.trim();
      var errorMatch = plain.match(/ERROR: AddressSanitizer: (.+)/i);
      var leakMatch = plain.match(/(Direct|Indirect) leak of ([\d,]+) byte\(s\) in ([\d,]+) object\(s\)/i);

      if (errorMatch) {
        finishCurrent();
        currentKind = "error";
        current = {
          type: errorMatch[1],
          severity: classifyAsanError(errorMatch[1]),
          frames: [],
          notes: [],
          rawBlock: [raw]
        };
        return;
      }

      if (leakMatch) {
        finishCurrent();
        currentKind = "leak";
        current = {
          leakType: leakMatch[1].toLowerCase() === "direct" ? "definitely" : "indirectly",
          bytes: normalizeNumber(leakMatch[2]),
          blocks: normalizeNumber(leakMatch[3]),
          recordIndex: 0,
          recordTotal: 0,
          frames: [],
          notes: [],
          rawBlock: [raw]
        };
        return;
      }

      if (!current) {
        return;
      }

      if (!plain) {
        current.rawBlock.push("");
        return;
      }

      if (/^SUMMARY:/i.test(plain)) {
        finishCurrent();
        return;
      }

      current.rawBlock.push(raw);
      if (/^#\d+\s+0x[0-9a-f]+/i.test(plain)) {
        current.frames.push(plain);
      } else {
        current.notes.push(plain);
      }
    });

    finishCurrent();

    var leakSummary = Object.keys(LEAK_TYPE_CONFIG).map(function (key) {
      var matches = leakRecords.filter(function (record) { return record.leakType === key; });
      return {
        leakType: key,
        label: LEAK_TYPE_CONFIG[key].label,
        severity: LEAK_TYPE_CONFIG[key].severity,
        impact: LEAK_TYPE_CONFIG[key].impact,
        bytes: matches.reduce(function (sum, record) { return sum + normalizeNumber(record.bytes); }, 0),
        blocks: matches.reduce(function (sum, record) { return sum + normalizeNumber(record.blocks); }, 0)
      };
    });

    return {
      metadata: {
        tool: /LeakSanitizer/i.test(text) ? "LeakSanitizer / AddressSanitizer" : "AddressSanitizer",
        version: "",
        pid: "",
        parentPid: "",
        command: ""
      },
      heapSummary: null,
      leakSummary: leakSummary,
      leakRecords: leakRecords,
      errorSummary: {
        errors: errorRecords.length,
        contexts: errorRecords.length,
        suppressedErrors: 0,
        suppressedContexts: 0
      },
      errorRecords: errorRecords,
      diagnostics: [{
        level: "ok",
        message: "Parser ASan montado a partir dos blocos ERROR e dos registros do LeakSanitizer."
      }]
    };
  }

  function classifyAsanError(type) {
    if (/heap-use-after-free|stack-use-after-return|double-free|heap-buffer-overflow|stack-buffer-overflow|use-after-poison/i.test(type)) {
      return "critical";
    }
    if (/alloc-dealloc-mismatch|odr-violation|container-overflow/i.test(type)) {
      return "high";
    }
    return "warning";
  }

  function initApp() {
    if (appInitialized) {
      return;
    }
    appInitialized = true;

    refs = {
      fileInput: document.getElementById("fileInput"),
      dropZone: document.getElementById("dropZone"),
      pasteInput: document.getElementById("pasteInput"),
      parsePasteBtn: document.getElementById("parsePasteBtn"),
      clearBtn: document.getElementById("clearBtn"),
      loadMessage: document.getElementById("loadMessage"),
      criticalCount: document.getElementById("criticalCount"),
      criticalMeta: document.getElementById("criticalMeta"),
      warningCount: document.getElementById("warningCount"),
      warningMeta: document.getElementById("warningMeta"),
      leakRecordCount: document.getElementById("leakRecordCount"),
      leakRecordMeta: document.getElementById("leakRecordMeta"),
      totalFindingCount: document.getElementById("totalFindingCount"),
      totalFindingMeta: document.getElementById("totalFindingMeta"),
      statusBanner: document.getElementById("statusBanner"),
      metaGrid: document.getElementById("metaGrid"),
      heapSummary: document.getElementById("heapSummary"),
      leakSummary: document.getElementById("leakSummary"),
      errorSummary: document.getElementById("errorSummary"),
      diagnosticsContent: document.getElementById("diagnosticsContent"),
      leakSearch: document.getElementById("leakSearch"),
      leakTypeFilter: document.getElementById("leakTypeFilter"),
      leakSort: document.getElementById("leakSort"),
      leakRecordsContent: document.getElementById("leakRecordsContent"),
      errorSearch: document.getElementById("errorSearch"),
      errorSeverityFilter: document.getElementById("errorSeverityFilter"),
      errorSort: document.getElementById("errorSort"),
      errorRecordsContent: document.getElementById("errorRecordsContent"),
      rawSearch: document.getElementById("rawSearch"),
      rawLogMeta: document.getElementById("rawLogMeta"),
      rawLogContent: document.getElementById("rawLogContent")
    };

    bindEvents();
    renderAll();
  }

  function bindEvents() {
    refs.fileInput.addEventListener("change", function (event) {
      var file = event.target.files && event.target.files[0];
      if (!file) {
        return;
      }
      readFile(file);
      refs.fileInput.value = "";
    });

    refs.dropZone.addEventListener("click", function () {
      refs.fileInput.click();
    });

    refs.dropZone.addEventListener("keydown", function (event) {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        refs.fileInput.click();
      }
    });

    ["dragenter", "dragover"].forEach(function (eventName) {
      refs.dropZone.addEventListener(eventName, function (event) {
        event.preventDefault();
        refs.dropZone.classList.add("drag-over");
      });
    });

    ["dragleave", "dragend", "drop"].forEach(function (eventName) {
      refs.dropZone.addEventListener(eventName, function (event) {
        event.preventDefault();
        refs.dropZone.classList.remove("drag-over");
      });
    });

    refs.dropZone.addEventListener("drop", function (event) {
      var file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
      if (file) {
        readFile(file);
      }
    });

    refs.parsePasteBtn.addEventListener("click", function () {
      var value = refs.pasteInput.value.trim();
      if (!value) {
        refs.loadMessage.textContent = "Cole o log completo antes de processar.";
        return;
      }
      applyText(value, "Texto colado");
    });

    refs.clearBtn.addEventListener("click", function () {
      state = createEmptyState();
      refs.pasteInput.value = "";
      refs.loadMessage.textContent = "Nenhum log carregado ainda.";
      renderAll();
    });

    refs.leakSearch.addEventListener("input", renderLeakRecords);
    refs.leakTypeFilter.addEventListener("change", renderLeakRecords);
    refs.leakSort.addEventListener("change", renderLeakRecords);
    refs.errorSearch.addEventListener("input", renderErrorRecords);
    refs.errorSeverityFilter.addEventListener("change", renderErrorRecords);
    refs.errorSort.addEventListener("change", renderErrorRecords);
    refs.rawSearch.addEventListener("input", renderRawLog);
  }

  function readFile(file) {
    var reader = new FileReader();
    reader.onload = function (event) {
      var text = String(event.target.result || "");
      refs.pasteInput.value = text;
      applyText(text, file.name);
    };
    reader.onerror = function () {
      refs.loadMessage.textContent = "Nao foi possivel ler o arquivo selecionado.";
    };
    reader.readAsText(file);
  }

  function applyText(text, label) {
    state = createAnalyzerState(text, label);
    refs.loadMessage.textContent =
      label + " carregado. Fonte detectada: " + state.source.toUpperCase() +
      ". " + formatCount(state.totalLines) + " linhas analisadas.";
    renderAll();
  }

  function renderAll() {
    renderStats();
    renderStatusBanner();
    renderMeta();
    renderHeapSummary();
    renderLeakSummary();
    renderErrorSummary();
    renderDiagnostics();
    renderLeakRecords();
    renderErrorRecords();
    renderRawLog();
  }

  function renderStats() {
    var critical = state.errorRecords.filter(function (record) { return record.severity === "critical"; }).length;
    var secondaryWarnings = state.errorRecords.filter(function (record) {
      return record.severity === "high" || record.severity === "warning";
    }).length;
    var totalFindings = state.leakRecords.length + state.errorRecords.length;
    var totalLeakBytes = state.leakRecords.reduce(function (sum, record) { return sum + normalizeNumber(record.bytes); }, 0);
    var totalLeakBlocks = state.leakRecords.reduce(function (sum, record) { return sum + normalizeNumber(record.blocks); }, 0);

    refs.criticalCount.textContent = formatCount(critical);
    refs.warningCount.textContent = formatCount(secondaryWarnings);
    refs.leakRecordCount.textContent = formatCount(state.leakRecords.length);
    refs.totalFindingCount.textContent = formatCount(totalFindings);

    refs.criticalMeta.textContent = critical ? "Requer revisao imediata" : "Sem erros criticos";
    refs.warningMeta.textContent = secondaryWarnings ? "Contextos de risco encontrados" : "Sem alertas de memoria";
    refs.leakRecordMeta.textContent = state.leakRecords.length
      ? formatBytes(totalLeakBytes) + " em " + formatCount(totalLeakBlocks) + " blocos"
      : "Nenhum leak registrado";
    refs.totalFindingMeta.textContent = totalFindings
      ? formatCount(state.errorRecords.length) + " erros + " + formatCount(state.leakRecords.length) + " loss records"
      : "Parser pronto para receber um log";
  }

  function renderStatusBanner() {
    if (!state.rawText) {
      refs.statusBanner.className = "status-banner empty";
      refs.statusBanner.textContent = "Carregue um log para gerar o resumo.";
      return;
    }

    var hasCritical = state.errorRecords.some(function (record) { return record.severity === "critical"; });
    var hasRiskyLeaks = state.leakSummary.some(function (entry) {
      return (entry.leakType === "definitely" || entry.leakType === "indirectly" || entry.leakType === "possibly") && entry.bytes > 0;
    });
    var onlyReachableLeaks = !hasRiskyLeaks && state.leakSummary.some(function (entry) {
      return entry.leakType === "reachable" && entry.bytes > 0;
    });
    var level = hasCritical ? "critical" : (state.errorRecords.length || hasRiskyLeaks) ? "warning" : "ok";
    var title = hasCritical
      ? "Status geral: atencao imediata"
      : (state.errorRecords.length || hasRiskyLeaks)
        ? "Status geral: revisar findings"
        : onlyReachableLeaks
          ? "Status geral: apenas still reachable"
          : "Status geral: sem findings relevantes";
    var summary = [
      "Fonte " + state.source.toUpperCase(),
      formatCount(state.errorRecords.length) + " blocos de erro",
      formatCount(state.leakRecords.length) + " loss records",
      formatCount(state.totalLines) + " linhas"
    ].join(" | ");

    refs.statusBanner.className = "status-banner status-" + level;
    refs.statusBanner.innerHTML =
      "<p class=\"banner-title\">" + escapeHtml(title) + "</p>" +
      "<p class=\"banner-meta\">" + escapeHtml(summary) + "</p>";
  }

  function renderMeta() {
    if (!state.rawText) {
      refs.metaGrid.innerHTML = "";
      return;
    }

    var cards = [
      { label: "Entrada", value: state.inputLabel || "Log carregado" },
      { label: "Fonte", value: state.source.toUpperCase() },
      { label: "PID", value: state.metadata.pid || "N/A" },
      { label: "Parent PID", value: state.metadata.parentPid || "N/A" },
      { label: "Tool", value: state.metadata.tool || "N/A" },
      { label: "Versao", value: state.metadata.version || "N/A" },
      { label: "Command", value: state.metadata.command || "N/A" },
      { label: "Linhas", value: formatCount(state.totalLines) }
    ];

    refs.metaGrid.innerHTML = cards.map(function (card) {
      return (
        "<article class=\"meta-card\">" +
          "<p class=\"meta-card-label\">" + escapeHtml(card.label) + "</p>" +
          "<p class=\"meta-card-value\">" + escapeHtml(card.value) + "</p>" +
        "</article>"
      );
    }).join("");
  }

  function renderHeapSummary() {
    if (!state.heapSummary) {
      refs.heapSummary.innerHTML = "<div class=\"empty-state\">Nenhum heap summary detectado nesse log.</div>";
      return;
    }

    var pendingOps = state.heapSummary.allocs - state.heapSummary.frees;
    refs.heapSummary.innerHTML =
      "<div class=\"metric-grid\">" +
        metricBox("Em uso na saida", formatBytes(state.heapSummary.inUseBytes), formatCount(state.heapSummary.inUseBlocks) + " blocos") +
        metricBox("Total alocado", formatBytes(state.heapSummary.totalAllocated), formatCount(state.heapSummary.allocs) + " allocs") +
        metricBox("Allocs / frees", formatCount(state.heapSummary.allocs) + " / " + formatCount(state.heapSummary.frees), formatCount(pendingOps) + " diferenca") +
      "</div>";
  }

  function metricBox(label, value, sub) {
    return (
      "<article class=\"metric-box\">" +
        "<p class=\"metric-label\">" + escapeHtml(label) + "</p>" +
        "<p class=\"metric-value\">" + escapeHtml(value) + "</p>" +
        "<p class=\"metric-sub\">" + escapeHtml(sub) + "</p>" +
      "</article>"
    );
  }

  function summaryStat(label, value) {
    return (
      "<div class=\"summary-stat-box\">" +
        "<p class=\"summary-stat-label\">" + escapeHtml(label) + "</p>" +
        "<p class=\"summary-stat-value\">" + escapeHtml(value) + "</p>" +
      "</div>"
    );
  }

  function renderLeakSummary() {
    if (!state.leakSummary.length) {
      refs.leakSummary.innerHTML = "<div class=\"empty-state\">Nenhum leak summary disponivel.</div>";
      return;
    }

    refs.leakSummary.innerHTML =
      "<div class=\"summary-stack\">" +
        state.leakSummary.map(function (entry) {
      var matchingRecords = state.leakRecords.filter(function (record) {
        return record.leakType === entry.leakType;
      }).length;

      return (
        "<article class=\"summary-row-card\">" +
          "<div class=\"summary-row-head\">" +
            "<div>" +
              "<span class=\"tag tag-" + severityTag(entry.severity) + "\">" + escapeHtml(entry.label) + "</span>" +
            "</div>" +
            "<p class=\"summary-row-title\">" + escapeHtml(formatBytes(entry.bytes)) + "</p>" +
          "</div>" +
          "<div class=\"summary-inline-stats\">" +
            summaryStat("Loss records", formatCount(matchingRecords)) +
            summaryStat("Blocos", formatCount(entry.blocks)) +
            summaryStat("Bytes", formatBytes(entry.bytes)) +
          "</div>" +
          "<p class=\"summary-row-impact\">" + escapeHtml(entry.impact) + "</p>" +
        "</article>"
      );
        }).join("") +
      "</div>";
  }

  function renderErrorSummary() {
    var grouped = {};

    state.errorRecords.forEach(function (record) {
      if (!grouped[record.type]) {
        grouped[record.type] = {
          severity: record.severity,
          count: 0,
          firstFrame: record.firstFrame || ""
        };
      }
      grouped[record.type].count += 1;
    });

    var rows = Object.keys(grouped).map(function (key) {
      return [key, grouped[key]];
    }).sort(function (left, right) {
      return severityOrder(left[1].severity) - severityOrder(right[1].severity);
    });

    if (!rows.length) {
      if (state.errorSummary) {
        refs.errorSummary.innerHTML =
          "<div class=\"summary-stack\">" +
            "<article class=\"summary-row-card\">" +
              "<div class=\"summary-row-head\">" +
                "<span class=\"tag tag-info\">Error summary</span>" +
                "<p class=\"summary-row-title\">" + escapeHtml(formatCount(state.errorSummary.errors) + " erros") + "</p>" +
              "</div>" +
              "<div class=\"summary-inline-stats\">" +
                summaryStat("Contextos", formatCount(state.errorSummary.contexts)) +
                summaryStat("Suprimidos", formatCount(state.errorSummary.suppressedErrors || 0)) +
                summaryStat("Parser", "Sem blocos individuais") +
              "</div>" +
              "<p class=\"summary-row-impact\">O log nao trouxe erros de memoria detalhados alem do resumo final.</p>" +
            "</article>" +
          "</div>";
      } else {
        refs.errorSummary.innerHTML = "<div class=\"empty-state\">Nenhum erro de memoria individual encontrado no log.</div>";
      }
      return;
    }

    refs.errorSummary.innerHTML =
      "<div class=\"summary-stack\">" +
        rows.map(function (item) {
          return (
            "<article class=\"summary-row-card\">" +
              "<div class=\"summary-row-head\">" +
                "<div>" +
                  "<span class=\"tag tag-" + severityTag(item[1].severity) + "\">" + escapeHtml(item[1].severity) + "</span>" +
                "</div>" +
                "<p class=\"summary-row-title\">" + escapeHtml(item[0]) + "</p>" +
              "</div>" +
              "<div class=\"summary-inline-stats\">" +
                summaryStat("Ocorrencias", formatCount(item[1].count)) +
                summaryStat("Primeira frame", simplifyFrame(item[1].firstFrame) || "N/A") +
                summaryStat("Fonte", "Valgrind / ASan") +
              "</div>" +
            "</article>"
          );
        }).join("") +
      "</div>";
  }

  function renderDiagnostics() {
    if (!state.diagnostics.length) {
      refs.diagnosticsContent.innerHTML = "<div class=\"empty-state\">Sem diagnosticos adicionais.</div>";
      return;
    }

    refs.diagnosticsContent.innerHTML =
      "<div class=\"diagnostics-list\">" +
        state.diagnostics.map(function (diagnostic) {
          return (
            "<div class=\"diagnostic-row " + escapeHtml(diagnostic.level) + "\">" +
              "<span class=\"tag tag-" + (diagnostic.level === "warn" ? "warning" : "success") + "\">" +
                escapeHtml(diagnostic.level === "warn" ? "Check" : "OK") +
              "</span>" +
              "<p class=\"record-muted\">" + escapeHtml(diagnostic.message) + "</p>" +
            "</div>"
          );
        }).join("") +
      "</div>";
  }

  function renderLeakRecords() {
    if (!state.leakRecords.length) {
      refs.leakRecordsContent.innerHTML = "<div class=\"empty-state\">Nenhum loss record detalhado para exibir.</div>";
      return;
    }

    var query = refs.leakSearch.value.trim().toLowerCase();
    var typeFilter = refs.leakTypeFilter.value;
    var sortBy = refs.leakSort.value;

    var records = state.leakRecords.filter(function (record) {
      if (typeFilter !== "all" && record.leakType !== typeFilter) {
        return false;
      }

      if (!query) {
        return true;
      }

      var haystack = [
        record.id,
        record.leakType,
        record.notes.join(" "),
        record.frames.join(" "),
        record.rawBlock.join(" ")
      ].join(" ").toLowerCase();

      return haystack.indexOf(query) >= 0;
    });

    records.sort(function (left, right) {
      if (sortBy === "bytes-desc") {
        return right.bytes - left.bytes;
      }
      if (sortBy === "bytes-asc") {
        return left.bytes - right.bytes;
      }
      if (sortBy === "type") {
        return left.leakType.localeCompare(right.leakType);
      }
      return (left.recordIndex || Number.MAX_SAFE_INTEGER) - (right.recordIndex || Number.MAX_SAFE_INTEGER);
    });

    if (!records.length) {
      refs.leakRecordsContent.innerHTML = "<div class=\"empty-state\">Nenhum loss record combina com os filtros atuais.</div>";
      return;
    }

    refs.leakRecordsContent.innerHTML = records.map(function (record) {
      var leakInfo = LEAK_TYPE_CONFIG[record.leakType] || LEAK_TYPE_CONFIG.reachable;
      var noteList = record.notes.length
        ? "<ul class=\"note-list\">" + record.notes.map(function (note) {
          return "<li>" + escapeHtml(note) + "</li>";
        }).join("") + "</ul>"
        : "<p class=\"record-muted\">Nenhuma nota adicional alem do stack trace.</p>";
      var stackTrace = record.frames.length
        ? "<pre class=\"code-block\">" + escapeHtml(record.frames.join("\n")) + "</pre>"
        : "<p class=\"record-muted\">Sem frames detalhadas nesse bloco.</p>";

      return (
        "<details class=\"record-card\">" +
          "<summary>" +
            "<div class=\"record-topline\">" +
              "<span class=\"tag tag-" + severityTag(leakInfo.severity) + "\">" + escapeHtml(leakInfo.label) + "</span>" +
              "<p class=\"record-title\">Loss record " + escapeHtml(record.id) + "</p>" +
              "<span class=\"record-muted\">" + escapeHtml(formatBytes(record.bytes) + " em " + formatCount(record.blocks) + " blocos") + "</span>" +
            "</div>" +
            "<div class=\"record-meta\">" +
              "<span class=\"record-muted\">" + escapeHtml(simplifyFrame(record.firstFrame || "Sem frame principal")) + "</span>" +
            "</div>" +
          "</summary>" +
          "<div class=\"record-body\">" +
            "<div class=\"record-body-grid\">" +
              "<section class=\"record-box\">" +
                "<h4>Notas capturadas</h4>" +
                noteList +
              "</section>" +
              "<section class=\"record-box\">" +
                "<h4>Stack trace</h4>" +
                stackTrace +
              "</section>" +
            "</div>" +
            "<section class=\"record-box\">" +
              "<h4>Trecho bruto do log</h4>" +
              "<pre class=\"code-block\">" + escapeHtml(record.rawBlock.join("\n")) + "</pre>" +
            "</section>" +
          "</div>" +
        "</details>"
      );
    }).join("");
  }

  function renderErrorRecords() {
    if (!state.errorRecords.length) {
      refs.errorRecordsContent.innerHTML = "<div class=\"empty-state\">Nenhum erro de memoria detalhado para exibir.</div>";
      return;
    }

    var query = refs.errorSearch.value.trim().toLowerCase();
    var severityFilter = refs.errorSeverityFilter.value;
    var sortBy = refs.errorSort.value;

    var records = state.errorRecords.filter(function (record) {
      if (severityFilter !== "all" && record.severity !== severityFilter) {
        return false;
      }

      if (!query) {
        return true;
      }

      var haystack = [
        record.type,
        record.notes.join(" "),
        record.frames.join(" "),
        record.rawBlock.join(" ")
      ].join(" ").toLowerCase();

      return haystack.indexOf(query) >= 0;
    });

    records.sort(function (left, right) {
      if (sortBy === "severity") {
        return severityOrder(left.severity) - severityOrder(right.severity);
      }
      if (sortBy === "type") {
        return left.type.localeCompare(right.type);
      }
      return Number(left.id) - Number(right.id);
    });

    if (!records.length) {
      refs.errorRecordsContent.innerHTML = "<div class=\"empty-state\">Nenhum erro combina com os filtros atuais.</div>";
      return;
    }

    refs.errorRecordsContent.innerHTML = records.map(function (record) {
      var noteList = record.notes.length
        ? "<ul class=\"note-list\">" + record.notes.map(function (note) {
          return "<li>" + escapeHtml(note) + "</li>";
        }).join("") + "</ul>"
        : "<p class=\"record-muted\">Sem notas extras nesse contexto.</p>";
      var stackTrace = record.frames.length
        ? "<pre class=\"code-block\">" + escapeHtml(record.frames.join("\n")) + "</pre>"
        : "<p class=\"record-muted\">Sem frames detalhadas nesse bloco.</p>";

      return (
        "<details class=\"record-card\">" +
          "<summary>" +
            "<div class=\"record-topline\">" +
              "<span class=\"tag tag-" + severityTag(record.severity) + "\">" + escapeHtml(record.severity) + "</span>" +
              "<p class=\"record-title\">" + escapeHtml(record.type) + "</p>" +
            "</div>" +
            "<div class=\"record-meta\">" +
              "<span class=\"record-muted\">" + escapeHtml(simplifyFrame(record.firstFrame || "Sem frame principal")) + "</span>" +
            "</div>" +
          "</summary>" +
          "<div class=\"record-body\">" +
            "<div class=\"record-body-grid\">" +
              "<section class=\"record-box\">" +
                "<h4>Notas capturadas</h4>" +
                noteList +
              "</section>" +
              "<section class=\"record-box\">" +
                "<h4>Stack trace</h4>" +
                stackTrace +
              "</section>" +
            "</div>" +
            "<section class=\"record-box\">" +
              "<h4>Trecho bruto do log</h4>" +
              "<pre class=\"code-block\">" + escapeHtml(record.rawBlock.join("\n")) + "</pre>" +
            "</section>" +
          "</div>" +
        "</details>"
      );
    }).join("");
  }

  function renderRawLog() {
    if (!state.rawText) {
      refs.rawLogMeta.textContent = "0 linhas";
      refs.rawLogContent.innerHTML = "<div class=\"empty-state\">O log bruto aparecera aqui sem truncamento.</div>";
      return;
    }

    var query = refs.rawSearch.value.trim();
    var lines = splitLines(state.rawText);
    var matchedLines = 0;

    refs.rawLogContent.innerHTML =
      "<ol class=\"raw-log-list\">" +
        lines.map(function (line, index) {
          if (query && String(line).toLowerCase().indexOf(query.toLowerCase()) >= 0) {
            matchedLines += 1;
          }

          return (
            "<li class=\"raw-log-line\">" +
              "<span class=\"line-no\">" + (index + 1) + "</span>" +
              "<code>" + highlightText(line, query) + "</code>" +
            "</li>"
          );
        }).join("") +
      "</ol>";

    refs.rawLogMeta.textContent = formatCount(lines.length) + " linhas" + (query ? " | " + formatCount(matchedLines) + " com destaque" : "");
  }

  function severityOrder(value) {
    if (value === "critical") { return 0; }
    if (value === "high") { return 1; }
    if (value === "warning") { return 2; }
    return 3;
  }

  function severityTag(value) {
    if (value === "critical") { return "critical"; }
    if (value === "high" || value === "warning") { return "warning"; }
    if (value === "success") { return "success"; }
    return "info";
  }

  function simplifyFrame(frame) {
    var text = String(frame || "").trim();
    if (!text) {
      return "";
    }
    var functionMatch = text.match(/(?:at|by)\s+0x[0-9a-f]+:\s*([^(]+)/i);
    if (functionMatch) {
      return functionMatch[1].trim();
    }
    return text;
  }

  var api = {
    detectSource: detectSource,
    parseValgrind: parseValgrind,
    parseAsan: parseAsan,
    createAnalyzerState: createAnalyzerState,
    formatBytes: formatBytes,
    formatCount: formatCount
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }

  global.MemoryAnalyzer = api;

  if (typeof document !== "undefined") {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", initApp, { once: true });
    } else {
      initApp();
    }
  }
})(typeof window !== "undefined" ? window : globalThis);
