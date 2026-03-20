// =========================
//  GLOBAL STATE
// =========================
let isAdminAuthenticated = false;
let eelReady = false;
let liveLogRefreshInterval = null;
let tabListenersAttached = false;
let lastLogId = 0;
let refreshInFlight = false;
const THEME_STORAGE_KEY = "usb-security-theme";
let allLogs = [];
let allQuarantineItems = [];
let activeLogFilters = {
  dateFrom: "",
  dateTo: "",
  severity: "",
  device: ""
};
let activeQuarantineFilters = {
  dateFrom: "",
  dateTo: ""
};

// Initialize on page load
document.addEventListener("DOMContentLoaded", () => {
  document.body.classList.add("app-ready");
  setupThemeToggle();
  waitForBackend();
  setupAutoRefresh();
  setupLoginOverlay();
  setupRefreshButtons();
  setupDateConstraints();
  setupLogFilters();
  setupQuarantineFilters();
  startClock();
});

function setupThemeToggle() {
  const savedTheme = localStorage.getItem(THEME_STORAGE_KEY) || "dark";
  applyTheme(savedTheme);

  const toggleBtn = document.getElementById("theme-toggle-btn");
  if (!toggleBtn) return;
  toggleBtn.addEventListener("click", toggleTheme);
}

function toggleTheme() {
  const isLight = document.body.classList.contains("light-mode");
  const nextTheme = isLight ? "dark" : "light";
  localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
  applyTheme(nextTheme);
}

function applyTheme(theme) {
  const isLight = theme === "light";
  document.body.classList.toggle("light-mode", isLight);

  const toggleBtn = document.getElementById("theme-toggle-btn");
  if (!toggleBtn) return;

  if (isLight) {
    toggleBtn.innerHTML = '<i class="fas fa-moon"></i> Dark Mode';
  } else {
    toggleBtn.innerHTML = '<i class="fas fa-sun"></i> Light Mode';
  }
}

function getTodayIsoDate() {
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, "0");
  const d = String(now.getDate()).padStart(2, "0");
  return `${y}-${m}-${d}`;
}

function clampDateToToday(value) {
  const v = String(value || "").trim();
  if (!v) return "";
  const today = getTodayIsoDate();
  return v > today ? today : v;
}

function setupDateConstraints() {
  const ids = ["logDateFrom", "logDateTo", "quarantineDateFrom", "quarantineDateTo"];
  const today = getTodayIsoDate();
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.max = today;
    const clamp = () => {
      const safe = clampDateToToday(el.value);
      if (safe !== el.value) el.value = safe;
    };
    el.addEventListener("input", clamp);
    el.addEventListener("change", clamp);
  });
}

function withTimeout(promise, ms, label = "operation") {
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(`${label} timed out`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timeoutId));
}

function renderLogsStatus(message) {
  const tbody = document.querySelector("#logTable tbody");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="4" class="empty-state">${escapeHtml(message)}</td></tr>`;
}

// Wait for backend bridge
function waitForBackend() {
  if (typeof eel !== "undefined") {
    eelReady = true;
    console.log("Backend bridge ready");
    // Expose callback for real-time logs
    eel.expose(addNewLog);
    // Expose notification function so Python can call eel.notifyFrontend(...)
    try { eel.expose(notifyFrontend); } catch (e) { console.warn("Failed to expose notifyFrontend:", e); }
  } else {
    setTimeout(waitForBackend, 400);
  }
}

function ensureBackendReady(timeoutMs = 4000) {
  if (eelReady) return Promise.resolve(true);
  const start = Date.now();
  return new Promise(resolve => {
    const tick = () => {
      if (eelReady) return resolve(true);
      if (Date.now() - start > timeoutMs) return resolve(false);
      setTimeout(tick, 100);
    };
    tick();
  });
}

// Real-time log callback from backend
function addNewLog(logEntry) {
  const normalized = normalizeLogEntry(logEntry);
  allLogs.unshift(normalized);
  if (allLogs.length > 500) allLogs = allLogs.slice(0, 500);
  updateFilterOptionsFromLogs(allLogs);

  if (!document.getElementById("tab-logs").classList.contains("hidden")) {
    applyLogFiltersAndRender(true);
  }
}

// Setup login overlay
function setupLoginOverlay() {
  const overlay = document.getElementById("login-overlay");
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) hideLogin();
  });
}

function setupRefreshButtons() {
  const refreshLogsBtn = document.getElementById("refreshLogsBtn");
  if (refreshLogsBtn) {
    refreshLogsBtn.addEventListener("click", async () => {
      await refreshLogs(true);
    });
  }

  const refreshQuarantineBtn = document.getElementById("refreshQuarantineBtn");
  if (refreshQuarantineBtn) {
    refreshQuarantineBtn.addEventListener("click", async () => {
      await refreshQuarantine(true);
    });
  }

  const clearLogsBtn = document.getElementById("clearLogsBtn");
  if (clearLogsBtn) {
    clearLogsBtn.addEventListener("click", async () => {
      await clearAllLogs();
    });
  }
}

// Login functions
function showLogin() {
  if (!eelReady) {
    notifyFrontend("Backend", "Backend not ready", "warning");
    return;
  }
  document.getElementById("login-overlay").classList.remove("hidden");
}

function hideLogin() {
  document.getElementById("login-overlay").classList.add("hidden");
  document.getElementById("login-error").textContent = "";
  document.getElementById("password").value = "";
}

async function login() {
  const user = document.getElementById("username").value.trim();
  const pass = document.getElementById("password").value;

  if (!user || !pass) {
    document.getElementById("login-error").textContent = "Please enter credentials";
    return;
  }

  try {
    const res = await eel.login(user, pass)();
    if (res.success) {
      hideLogin();
      setAdminAuthenticated(true);
    } else {
      document.getElementById("login-error").textContent = res.message || "Login failed";
    }
  } catch (e) {
    document.getElementById("login-error").textContent = "Connection error";
    console.error(e);
  }
}

// Admin authentication
eel.expose(setAdminAuthenticated);
function setAdminAuthenticated(auth) {
  isAdminAuthenticated = auth;
  const adminPanelBtn = document.getElementById("admin-panel-btn");
  document.getElementById("admin-tabs").classList.toggle("hidden", !auth);
  document.getElementById("admin-dashboard").classList.toggle("hidden", !auth);
  document.getElementById("back-to-main").classList.toggle("hidden", !auth);
  document.getElementById("user-view").classList.toggle("hidden", auth);
  if (adminPanelBtn) adminPanelBtn.disabled = auth;

  if (auth) {
    attachTabListeners();
    loadSettings();
    refreshLogs();
    startLiveLogRefresh();
    refreshAll();
  } else {
    stopLiveLogRefresh();
  }
}

function startClock() {
  const timeEl = document.getElementById("clockTime");
  const dateEl = document.getElementById("clockDate");
  if (!timeEl || !dateEl) return;

  const update = () => {
    const now = new Date();
    const time = now.toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    });
    const date = now.toLocaleDateString(undefined, {
      weekday: "short",
      month: "short",
      day: "2-digit"
    });
    timeEl.textContent = time;
    dateEl.textContent = date;
  };

  update();
  setInterval(update, 1000);
}

function backToMain() {
  setAdminAuthenticated(false);
}

// Tab handling
function attachTabListeners() {
  if (tabListenersAttached) return;
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
      const name = tab.dataset.tab;
      
      document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.add("hidden"));
      
      tab.classList.add("active");
      document.getElementById(`tab-${name}`).classList.remove("hidden");

      if (name === "logs") {
        refreshLogs();
      } else {
        if (name === "quarantine") refreshQuarantine();
        if (name === "settings") loadSettings();
      }
    });
  });
  tabListenersAttached = true;
}

// Refresh scan progress
async function refreshAll() {
  try {
    const s = await eel.get_scan_progress()();
    
    if (!s) {
      console.error("No scan progress data received");
      return;
    }

    // Update progress bars
    const progressPercent = Math.min(Math.max(s.percentage || 0, 0), 100);
    document.getElementById("progressFill").style.width = `${progressPercent}%`;
    document.getElementById("progressFillAdmin").style.width = `${progressPercent}%`;
    
    // Update progress text
    const text = `${s.files_scanned || 0}/${s.total_files || 0} (${progressPercent}%)`;
    document.getElementById("progressText").textContent = text;
    document.getElementById("progressTextAdmin").textContent = text;

    // Update current file
    const file = s.current_file ? `Scanning: ${s.current_file}` : "";
    document.getElementById("currentFile").textContent = file;
    document.getElementById("currentFileAdmin").textContent = file;

    // Update scan status
    const status = s.scanning
      ? `Scanning ${s.drive || "USB"}`
      : (s.files_scanned > 0 ? `Last scan completed (${s.drive || "USB"})` : "Idle");
    document.getElementById("scanStatus").textContent = status;
    document.getElementById("scanStatusAdmin").textContent = status;

    // Update USB message
    let msg, cls;
    if (s.scanning) {
      msg = "Scanning USB...";
      cls = "usb-message scanning";
    } else if (s.threats_found > 0) {
      msg = `Threats found (${s.threats_found})`;
      cls = "usb-message threat";
    } else if (s.files_scanned > 0) {
      msg = "USB is clean";
      cls = "usb-message clean";
    } else {
      msg = "No USB detected";
      cls = "usb-message";
    }
    document.getElementById("usbMessage").textContent = msg;
    document.getElementById("usbMessage").className = cls;

    // Update USB device counters
    updateUSBDeviceCounters(s);
    updateActionButtons(s);
  } catch (e) {
    console.error("refreshAll failed:", e);
  }
}

function updateActionButtons(scanData) {
  const ejectBtn = document.getElementById("ejectUsbBtn");
  if (ejectBtn) ejectBtn.disabled = Boolean(scanData && scanData.scanning);
}

async function ejectUsb() {
  try {
    const scan = await eel.get_scan_progress?.()();
    if (scan && scan.scanning) {
      notifyFrontend("USB Eject", "Cannot eject while scan is in progress", "warning");
      return;
    }

    const btn = document.getElementById("ejectUsbBtn");
    const previous = btn ? btn.innerHTML : "";
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Ejecting...';
    }
    const res = await eel.eject_usb?.()();
    if (!res || !res.success) {
      notifyFrontend("USB Eject", (res && res.message) || "Eject failed", "warning");
      return;
    }
    notifyFrontend("USB Eject", res.message || "Eject requested", "success");
  } catch (e) {
    console.error("ejectUsb failed:", e);
    notifyFrontend("USB Eject", "Failed to eject USB", "danger");
  } finally {
    const btn = document.getElementById("ejectUsbBtn");
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="fas fa-eject"></i> Eject USB';
    }
  }
}

// Update USB device counters in dashboard
function updateUSBDeviceCounters(scanData) {
  try {
    const scanningEl = document.getElementById("scanningDevices");
    const threatsEl = document.getElementById("threatsFound");

    if (!scanningEl || !threatsEl) {
      console.warn("Device counter elements not found");
      return;
    }

    const scanningCount = scanData.scanning ? 1 : 0;
    const threatsCount = scanData.threats_found ? Math.max(parseInt(scanData.threats_found), 0) : 0;
    console.log("Device counts:", { scanningCount, threatsCount });

    // Update counter displays with transition effect
    updateCounterValue(scanningEl, scanningCount);
    updateCounterValue(threatsEl, threatsCount);

    // Get card containers and add pulse animation
    const scanningCard = scanningEl.closest(".device-card");
    const threatsCard = threatsEl.closest(".device-card");

    if (scanningCard) {
      if (scanningCount > 0) {
        scanningCard.classList.add("active-pulse");
      } else {
        scanningCard.classList.remove("active-pulse");
      }
    }

    if (threatsCard) {
      if (threatsCount > 0) {
        threatsCard.classList.add("active-pulse");
      } else {
        threatsCard.classList.remove("active-pulse");
      }
    }
  } catch (e) {
    console.error("Error updating USB counters:", e);
  }
}

// Helper function to update counter with animation
function updateCounterValue(element, newValue) {
  const currentValue = parseInt(element.textContent) || 0;
  
  if (currentValue !== newValue) {
    element.style.transition = "all 0.3s ease";
    element.style.transform = "scale(0.95)";
    element.textContent = newValue;
    
    setTimeout(() => {
      element.style.transform = "scale(1)";
    }, 150);
  }
}

// Helper to check YARA rules status
async function checkYaraStatus() {
  try {
    if (!eelReady) return;
    const status = await eel.get_yara_status?.()() || { loaded: false, count: 0 };
    console.log("YARA Status:", status);
    return status;
  } catch (e) {
    console.error("Error checking YARA status:", e);
    return { loaded: false, count: 0 };
  }
}

// Log functions
async function refreshLogs(isManual = false) {
  try {
    if (refreshInFlight) return;
    refreshInFlight = true;
    const ready = await ensureBackendReady();
    if (!ready) {
      renderLogsStatus("Backend not ready");
      return;
    }
    
    if (!eel.get_logs) {
      renderLogsStatus("Log service unavailable");
      return;
    }

    const logs = await withTimeout(eel.get_logs(200)(), 5000, "get_logs");
    allLogs = (logs || []).map(normalizeLogEntry);
    updateFilterOptionsFromLogs(allLogs);
    applyLogFiltersAndRender(false);

    // Track highest ID for incremental polling.
    const maxId = logs && logs.length ? Math.max(...logs.map(l => Number(l.id) || 0)) : 0;
    lastLogId = maxId;
    if (isManual) {
      const btn = document.getElementById("refreshLogsBtn");
      if (btn) {
        btn.classList.add("active");
        setTimeout(() => btn.classList.remove("active"), 250);
      }
    }
  } catch (e) {
    renderLogsStatus("Failed to refresh logs. Check backend status.");
    console.error("refreshLogs failed:", e);
  } finally {
    refreshInFlight = false;
  }
}

async function clearAllLogs() {
  const ready = await ensureBackendReady();
  if (!ready) {
    notifyFrontend("Logs", "Backend not ready", "warning");
    return;
  }
  if (typeof eel.clear_logs !== "function") {
    notifyFrontend("Logs", "Clear logs service unavailable", "warning");
    return;
  }

  const proceed = await showConfirmDialog("Clear all logs? This cannot be undone.", "Confirm Clear");
  if (!proceed) return;

  const clearBtn = document.getElementById("clearLogsBtn");
  const previousLabel = clearBtn ? clearBtn.innerHTML : "";
  try {
    if (clearBtn) {
      clearBtn.disabled = true;
      clearBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Clearing...';
    }

    const res = await eel.clear_logs()();
    if (!res || !res.success) {
      throw new Error((res && res.message) || "Failed to clear logs");
    }

    allLogs = [];
    lastLogId = 0;
    updateFilterOptionsFromLogs(allLogs);
    applyLogFiltersAndRender(false);
    renderLogsStatus("No logs available");
  } catch (e) {
    console.error("clearAllLogs failed:", e);
    notifyFrontend("Logs", "Failed to clear logs", "danger");
  } finally {
    if (clearBtn) {
      clearBtn.disabled = false;
      clearBtn.innerHTML = previousLabel || '<i class="fas fa-trash-alt"></i> Clear All Logs';
    }
  }
}

function setupLogFilters() {
  const ids = ["logDateFrom", "logDateTo", "logSeverityFilter", "logDeviceFilter"];
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener("change", () => {
      activeLogFilters = collectLogFilters();
      applyLogFiltersAndRender(false);
    });
  });
}

function collectLogFilters() {
  return {
    dateFrom: clampDateToToday(document.getElementById("logDateFrom")?.value || ""),
    dateTo: clampDateToToday(document.getElementById("logDateTo")?.value || ""),
    severity: document.getElementById("logSeverityFilter")?.value || "",
    device: document.getElementById("logDeviceFilter")?.value || ""
  };
}

function updateFilterOptionsFromLogs(logs) {
  const deviceSelect = document.getElementById("logDeviceFilter");
  if (!deviceSelect) return;

  const selectedDevice = deviceSelect.value;
  const deviceOptions = [...new Set(logs.map(l => l.device).filter(Boolean))].sort();

  deviceSelect.innerHTML = `<option value="">All</option>${deviceOptions.map(d => `<option value="${escapeHtml(d)}">${escapeHtml(d)}</option>`).join("")}`;

  if (deviceOptions.includes(selectedDevice)) deviceSelect.value = selectedDevice;
  activeLogFilters = collectLogFilters();
}

function applyLogFiltersAndRender(markNewRows = false) {
  const f = activeLogFilters;
  const filtered = allLogs.filter(log => {
    const logDate = parseLogTimestamp(log.timestamp);
    const fromOk = !f.dateFrom || (logDate && logDate >= new Date(`${f.dateFrom}T00:00:00`));
    const toOk = !f.dateTo || (logDate && logDate <= new Date(`${f.dateTo}T23:59:59`));
    const sevOk = !f.severity || log.severity === f.severity;
    const devOk = !f.device || log.device === f.device;
    return fromOk && toOk && sevOk && devOk;
  });

  renderLogs(filtered, markNewRows);
}

function renderLogs(logs, markNewRows = false) {
  const tbody = document.querySelector("#logTable tbody");
  if (!tbody) return;

  tbody.innerHTML = "";
  if (!logs || logs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No logs match the selected filters</td></tr>`;
    return;
  }

  logs.forEach((log, idx) => {
    const row = document.createElement("tr");
    if (markNewRows && idx === 0) row.className = "new-log";
    row.innerHTML = `
      <td>${escapeHtml(log.timestamp || "N/A")}</td>
      <td><span class="log-severity severity-${escapeHtml(log.severity || "info")}">${escapeHtml(log.severity || "info")}</span></td>
      <td><span class="log-type ${logTypeClass(log.type)}">${escapeHtml(log.type || "INFO")}</span></td>
      <td>${escapeHtml(String(log.id ?? "N/A"))}</td>`;
    tbody.appendChild(row);
  });
}

function normalizeLogEntry(log) {
  const details = String(log?.details || "");
  const type = String(log?.type || "INFO");
  const rawTimestamp = String(log?.timestamp || "").trim();
  const timestamp = /^\d{2}:\d{2}:\d{2}$/.test(rawTimestamp)
    ? `${new Date().toISOString().slice(0, 10)} ${rawTimestamp}`
    : (rawTimestamp || new Date().toISOString());
  const filename = extractField(details, [
    /in\s+([A-Za-z0-9_.\\/-]+\.[A-Za-z0-9]+)/i,
    /file[:=\s]+([A-Za-z0-9_.\\/-]+\.[A-Za-z0-9]+)/i
  ]);
  const device = extractField(details, [
    /\b([A-Z]:\\?)/i,
    /drive[:=\s]+([A-Za-z0-9_:\\/-]+)/i,
    /device[:=\s]+([A-Za-z0-9_:\\/-]+)/i
  ]);
  const signature = extractField(details, [
    /signature[:=\s]+([A-Za-z0-9_.-]+)/i,
    /threat[:=\s]+([A-Za-z0-9_.-]+)/i
  ]) || (type === "THREAT" ? "Suspicious content" : "");

  return {
    id: log?.id || 0,
    timestamp,
    type,
    details,
    filename,
    device,
    signature,
    severity: deriveSeverity(type, details),
    action: deriveAction(type, details)
  };
}

function extractField(text, patterns) {
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match && match[1]) return match[1].trim();
  }
  return "";
}

function parseLogTimestamp(timestamp) {
  const value = String(timestamp || "").trim();
  if (!value) return null;

  // Handles "YYYY-MM-DD HH:mm:ss" and "YYYY-MM-DDTHH:mm:ss(.sss)"
  const m = value.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?/);
  if (m) {
    const [, y, mo, d, h, mi, s = "00"] = m;
    return new Date(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s));
  }

  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function deriveSeverity(type, details) {
  const t = String(type || "").toUpperCase();
  if (t === "ZIP_QUARANTINED") return "low";
  if (t.includes("MALWARE") || t === "YARA_MATCH" || t === "THREAT_FOUND" || t === "THREAT") return "critical";
  return "info";
}

function deriveAction(type, details) {
  const text = `${type} ${details}`.toLowerCase();
  if (text.includes("quarantine")) return "Quarantined";
  if (text.includes("deleted")) return "Deleted";
  if (text.includes("restored")) return "Restored";
  if (text.includes("blocked")) return "Blocked";
  if (type === "THREAT") return "Flagged";
  if (type === "SCAN") return "Scanned";
  return "Logged";
}

function logTypeClass(type) {
  const t = String(type || "").toLowerCase();
  if (t.includes("threat") || t.includes("error")) return "log-error";
  if (t.includes("scan")) return "log-scan";
  if (t.includes("warn") || t.includes("quarantine")) return "log-warning";
  return "log-info";
}

function startLiveLogRefresh() {
  if (liveLogRefreshInterval) clearInterval(liveLogRefreshInterval);
  // Poll backend every second for new logs.
  liveLogRefreshInterval = setInterval(async () => {
    try {
      if (!eelReady) return;
      const newLogs = await eel.get_new_logs?.(lastLogId)?.() || [];
      if (newLogs && newLogs.length > 0) {
        newLogs.forEach(log => addNewLog(log));
        // Update lastLogId to the highest new ID
        if (newLogs[newLogs.length - 1].id) {
          lastLogId = newLogs[newLogs.length - 1].id;
        }
      }
    } catch (e) {
      console.error("Error fetching new logs:", e);
    }
  }, 1000);
}

function stopLiveLogRefresh() {
  if (liveLogRefreshInterval) clearInterval(liveLogRefreshInterval);
}

function setupQuarantineFilters() {
  const ids = ["quarantineDateFrom", "quarantineDateTo"];
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener("change", () => {
      activeQuarantineFilters = collectQuarantineFilters();
      renderQuarantineTable();
    });
  });
}

function collectQuarantineFilters() {
  return {
    dateFrom: clampDateToToday(document.getElementById("quarantineDateFrom")?.value || ""),
    dateTo: clampDateToToday(document.getElementById("quarantineDateTo")?.value || "")
  };
}

function getQuarantineFileName(item) {
  if (item?.file_name) return String(item.file_name);
  if (item?.original_path) {
    const normalized = String(item.original_path).replace(/\\/g, "/");
    const parts = normalized.split("/");
    return parts[parts.length - 1] || "N/A";
  }
  if (item?.filename) {
    const m = String(item.filename).match(/^\d{8}_\d{6}_(.+)$/);
    return m ? m[1] : String(item.filename);
  }
  return "N/A";
}

function renderQuarantineTable() {
  const tbody = document.querySelector("#quarantineTable tbody");
  if (!tbody) return;

  const filters = activeQuarantineFilters;
  const filtered = allQuarantineItems.filter(item => {
    const itemDate = parseLogTimestamp(item.quarantined_at);
    const fromOk = !filters.dateFrom || (itemDate && itemDate >= new Date(`${filters.dateFrom}T00:00:00`));
    const toOk = !filters.dateTo || (itemDate && itemDate <= new Date(`${filters.dateTo}T23:59:59`));
    return fromOk && toOk;
  });

  tbody.innerHTML = "";

  if (!filtered || filtered.length === 0) {
    const message = allQuarantineItems.length
      ? "No quarantined files match the selected date range"
      : "No quarantined files";
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state">${message}</td></tr>`;
    return;
  }

  filtered.forEach(i => {
    const row = document.createElement("tr");

    const dateCell = document.createElement("td");
    dateCell.textContent = i.quarantined_at || "N/A";

    const fileNameCell = document.createElement("td");
    fileNameCell.textContent = getQuarantineFileName(i);

    const pathCell = document.createElement("td");
    pathCell.textContent = i.original_path || "N/A";

    const reasonCell = document.createElement("td");
    reasonCell.textContent = i.reason || "N/A";

    const actionsCell = document.createElement("td");
    actionsCell.className = "actions";

    const restoreBtn = document.createElement("button");
    restoreBtn.type = "button";
    restoreBtn.className = "btn-small";
    restoreBtn.textContent = "Restore";
    restoreBtn.addEventListener("click", () => restoreItem(i.filename));

    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "btn-small";
    deleteBtn.textContent = "Delete";
    deleteBtn.addEventListener("click", () => deleteItem(i.filename));

    actionsCell.appendChild(restoreBtn);
    actionsCell.appendChild(deleteBtn);

    row.appendChild(dateCell);
    row.appendChild(fileNameCell);
    row.appendChild(pathCell);
    row.appendChild(reasonCell);
    row.appendChild(actionsCell);
    tbody.appendChild(row);
  });
}

function showConfirmDialog(message, title = "Confirm") {
  return new Promise(resolve => {
    const overlay = document.createElement("div");
    overlay.style.position = "fixed";
    overlay.style.inset = "0";
    overlay.style.background = "rgba(0, 0, 0, 0.55)";
    overlay.style.display = "flex";
    overlay.style.alignItems = "center";
    overlay.style.justifyContent = "center";
    overlay.style.zIndex = "2500";

    const box = document.createElement("div");
    box.style.width = "min(460px, 92vw)";
    box.style.background = "#0f1e18";
    box.style.border = "1px solid rgba(0, 209, 125, 0.28)";
    box.style.borderRadius = "12px";
    box.style.padding = "18px";
    box.style.boxShadow = "0 16px 45px rgba(0, 0, 0, 0.55)";
    box.style.color = "#dbffe9";

    const h = document.createElement("h3");
    h.textContent = title;
    h.style.margin = "0 0 10px 0";
    h.style.fontSize = "1.05rem";

    const p = document.createElement("p");
    p.textContent = message;
    p.style.margin = "0 0 14px 0";
    p.style.fontSize = "0.95rem";

    const actions = document.createElement("div");
    actions.style.display = "flex";
    actions.style.gap = "10px";
    actions.style.justifyContent = "flex-end";

    const cancelBtn = document.createElement("button");
    cancelBtn.className = "btn btn-secondary";
    cancelBtn.type = "button";
    cancelBtn.textContent = "Cancel";

    const okBtn = document.createElement("button");
    okBtn.className = "btn btn-danger";
    okBtn.type = "button";
    okBtn.textContent = "Confirm";

    const done = (value) => {
      if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
      resolve(value);
    };

    cancelBtn.addEventListener("click", () => done(false));
    okBtn.addEventListener("click", () => done(true));
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) done(false);
    });

    actions.appendChild(cancelBtn);
    actions.appendChild(okBtn);
    box.appendChild(h);
    box.appendChild(p);
    box.appendChild(actions);
    overlay.appendChild(box);
    document.body.appendChild(overlay);
  });
}

// Quarantine functions
async function refreshQuarantine(isManual = false) {
  try {
    const ready = await ensureBackendReady();
    if (!ready) return;

    const list = await eel.get_quarantine_list()();
    allQuarantineItems = list || [];
    activeQuarantineFilters = collectQuarantineFilters();
    renderQuarantineTable();

    if (isManual) {
      const btn = document.getElementById("refreshQuarantineBtn");
      if (btn) {
        btn.classList.add("active");
        setTimeout(() => btn.classList.remove("active"), 250);
      }
    }
  } catch (e) {
    console.error("refreshQuarantine failed:", e);
  }
}

async function restoreItem(f) {
  const ok = await showConfirmDialog("Restore file?", "Restore");
  if (!ok) return;
  try {
    const res = await eel.restore_quarantine_item(f)();
    if (!res || !res.success) {
      notifyFrontend("Quarantine", (res && res.message) || "Restore failed", "warning");
      return;
    }
    notifyFrontend("Quarantine", "File restored", "success");
    setTimeout(refreshQuarantine, 400);
  } catch (e) {
    console.error("restoreItem failed:", e);
    notifyFrontend("Quarantine", "Restore failed", "danger");
  }
}

async function deleteItem(f) {
  const ok = await showConfirmDialog("Delete permanently?", "Delete");
  if (!ok) return;
  try {
    const res = await eel.delete_quarantine_item(f)();
    if (!res || !res.success) {
      notifyFrontend("Quarantine", (res && res.message) || "Delete failed", "warning");
      return;
    }
    notifyFrontend("Quarantine", "File deleted", "success");
    setTimeout(refreshQuarantine, 400);
  } catch (e) {
    console.error("deleteItem failed:", e);
    notifyFrontend("Quarantine", "Delete failed", "danger");
  }
}

async function clearQuarantine() {
  const ok = await showConfirmDialog("Clear all quarantined files?", "Clear Quarantine");
  if (!ok) return;
  try {
    const res = await eel.clear_quarantine?.()();
    if (!res || !res.success) {
      notifyFrontend("Quarantine", (res && res.message) || "Clear failed", "warning");
      return;
    }
    notifyFrontend("Quarantine", "Quarantine cleared", "success");
    setTimeout(refreshQuarantine, 400);
  } catch (e) {
    console.error("clearQuarantine failed:", e);
    notifyFrontend("Quarantine", "Clear failed", "danger");
  }
}

// Helper functions
function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

// Auto refresh
function setupAutoRefresh() {
  // Faster polling makes short scans visible in UI.
  setInterval(refreshAll, 250);
}

function notifyFrontend(title, message, level = "info") {
  try {
    // Offline fallback when Toastify CDN is unavailable.
    if (typeof Toastify !== "function") {
      let host = document.getElementById("toastHost");
      if (!host) {
        host = document.createElement("div");
        host.id = "toastHost";
        host.style.position = "fixed";
        host.style.top = "12px";
        host.style.right = "12px";
        host.style.zIndex = "5000";
        host.style.display = "flex";
        host.style.flexDirection = "column";
        host.style.gap = "8px";
        host.style.pointerEvents = "none";
        document.body.appendChild(host);
      }

      const toast = document.createElement("div");
      toast.style.pointerEvents = "auto";
      toast.style.minWidth = "280px";
      toast.style.maxWidth = "560px";
      toast.style.borderRadius = "10px";
      toast.style.padding = "12px 14px";
      toast.style.color = "#fff";
      toast.style.boxShadow = "0 8px 30px rgba(0,0,0,0.25)";
      toast.style.background =
        level === "danger"
          ? "linear-gradient(90deg, #ff416c 0%, #ff4b2b 100%)"
          : level === "warning"
          ? "linear-gradient(90deg, #f2994a 0%, #f2c94c 100%)"
          : level === "success"
          ? "linear-gradient(90deg, #26a69a 0%, #2bb673 100%)"
          : "linear-gradient(90deg, #343a40, #212529)";

      const t = document.createElement("div");
      t.style.fontWeight = "800";
      t.textContent = String(title || "");
      const m = document.createElement("div");
      m.style.marginTop = "4px";
      m.textContent = String(message || "");

      if (title) toast.appendChild(t);
      toast.appendChild(m);
      host.appendChild(toast);
      setTimeout(() => {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, level === "danger" ? 12000 : 6000);
      return;
    }

    const content = document.createElement("div");
    content.style.lineHeight = "1.15";
    content.style.display = "flex";
    content.style.flexDirection = "row";
    content.style.gap = "10px";
    content.style.alignItems = "center";

    const icon = document.createElement("div");
    icon.style.flex = "0 0 auto";
    icon.style.display = "flex";
    icon.style.alignItems = "center";
    icon.style.justifyContent = "center";
    if (level === "danger") {
      icon.innerHTML = '<i class="fas fa-exclamation-triangle" style="font-size:26px;color:#fff"></i>';
    } else if (level === "warning") {
      icon.innerHTML = '<i class="fas fa-exclamation-circle" style="font-size:24px;color:#fff"></i>';
    } else if (level === "success") {
      icon.innerHTML = '<i class="fas fa-check-circle" style="font-size:24px;color:#fff"></i>';
    } else {
      icon.innerHTML = '<i class="fas fa-info-circle" style="font-size:22px;color:#fff"></i>';
    }

    const textWrap = document.createElement("div");
    textWrap.style.display = "flex";
    textWrap.style.flexDirection = "column";
    textWrap.style.gap = "6px";

    const titleEl = document.createElement("div");
    titleEl.innerHTML = escapeHtml(title || "");
    titleEl.style.fontWeight = "800";
    titleEl.style.fontSize = (level === "danger" ? "1.15rem" : "1.05rem");
    titleEl.style.letterSpacing = "0.2px";

    const msgEl = document.createElement("div");
    msgEl.innerHTML = escapeHtml(message || "");
    msgEl.style.fontSize = (level === "danger" ? "1.05rem" : "0.95rem");

    textWrap.appendChild(titleEl);
    textWrap.appendChild(msgEl);
    content.appendChild(icon);
    content.appendChild(textWrap);

    let style = {
      color: "#fff",
      boxShadow: "0 8px 30px rgba(0,0,0,0.18)",
      borderRadius: "10px",
      padding: "16px 18px",
      maxWidth: "620px"
    };

    let duration = 6000;

    if (level === "danger") {
      style.background = "linear-gradient(90deg, #ff416c 0%, #ff4b2b 100%)";
      style.border = "2px solid rgba(255,255,255,0.12)";
      duration = 14000;
      titleEl.style.fontSize = "1.25rem";
      msgEl.style.fontSize = "1.1rem";
      content.style.transform = "scale(1.03)";
    } else if (level === "warning") {
      style.background = "linear-gradient(90deg, #f2994a 0%, #f2c94c 100%)";
      style.color = "#1f2937";
      style.border = "1px solid rgba(255,255,255,0.28)";
    } else if (level === "success") {
      style.background = "linear-gradient(90deg, #26a69a 0%, #2bb673 100%)";
    } else {
      style.background = "linear-gradient(90deg, #343a40, #212529)";
    }

    Toastify({
      node: content,
      duration: duration,
      gravity: "top",
      position: "right",
      close: true,
      stopOnFocus: true,
      style: style
    }).showToast();
  } catch (e) {
    console.error("notifyFrontend error:", e);
  }
}

