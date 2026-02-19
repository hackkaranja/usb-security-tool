// =========================
//  GLOBAL STATE
// =========================
let isAdminAuthenticated = false;
let eelReady = false;
let liveLogRefreshInterval = null;
let lastLogId = 0;
let refreshInFlight = false;

// Initialize on page load
document.addEventListener("DOMContentLoaded", () => {
  waitForEel();
  setupAutoRefresh();
  setupLoginOverlay();
  setupLogRefreshButton();
});

// Wait for EEL backend
function waitForEel() {
  if (typeof eel !== "undefined") {
    eelReady = true;
    console.log("EEL ready");
    // Expose callback for real-time logs
    eel.expose(addNewLog);
    // Expose notification function so Python can call eel.notifyFrontend(...)
    try { eel.expose(notifyFrontend); } catch (e) { console.warn("Failed to expose notifyFrontend:", e); }
  } else {
    setTimeout(waitForEel, 400);
  }
}

function ensureEelReady(timeoutMs = 4000) {
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
  if (!document.getElementById("tab-logs").classList.contains("hidden")) {
    const tbody = document.querySelector("#logTable tbody");
    if (!tbody) return;

    // Remove loading/empty state if present
    const emptyRow = tbody.querySelector(".empty-state");
    if (emptyRow) emptyRow.parentElement.remove();

    // Add new log row
    const row = document.createElement("tr");
    row.className = "log-row new-log";
    row.innerHTML = `
      <td>${escapeHtml(logEntry.timestamp || new Date().toLocaleTimeString())}</td>
      <td><span class="log-type log-${(logEntry.type || "info").toLowerCase()}">${escapeHtml(logEntry.type || "INFO")}</span></td>
      <td>${escapeHtml(logEntry.details || "")}</td>`;
    tbody.insertBefore(row, tbody.firstChild);

    // Keep only last 500 logs
    while (tbody.children.length > 500) {
      tbody.removeChild(tbody.lastChild);
    }

    // Animate new row
    row.style.animation = "slideDown 0.3s ease";

    // Auto-scroll if at bottom
    const container = document.querySelector("#tab-logs .table-container");
    if (container && container.scrollTop + container.clientHeight >= container.scrollHeight - 50) {
      setTimeout(() => {
        container.scrollTop = container.scrollHeight;
      }, 100);
    }
  }
}

// Setup login overlay
function setupLoginOverlay() {
  const overlay = document.getElementById("login-overlay");
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) hideLogin();
  });
}

function setupLogRefreshButton() {
  const btn = document.getElementById("refreshLogsBtn");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    await refreshLogs(true);
    if (!document.getElementById("tab-logs").classList.contains("hidden")) {
      startLiveLogRefresh();
    }
  });
}

// Login functions
function showLogin() {
  if (!eelReady) return alert("Backend not ready");
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
  document.getElementById("admin-tabs").classList.toggle("hidden", !auth);
  document.getElementById("admin-dashboard").classList.toggle("hidden", !auth);
  document.getElementById("back-to-main").classList.toggle("hidden", !auth);
  document.getElementById("user-view").classList.toggle("hidden", auth);

  if (auth) {
    attachTabListeners();
    loadSettings();
    refreshAll();
  }
}

function backToMain() {
  setAdminAuthenticated(false);
}

// Tab handling
function attachTabListeners() {
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
      const name = tab.dataset.tab;
      
      document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.add("hidden"));
      
      tab.classList.add("active");
      document.getElementById(`tab-${name}`).classList.remove("hidden");

      if (name === "logs") {
        refreshLogs();
        startLiveLogRefresh();
      } else {
        stopLiveLogRefresh();
        if (name === "quarantine") refreshQuarantine();
        if (name === "settings") loadSettings();
      }
    });
  });
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
    const status = s.scanning ? `Scanning ${s.drive || "USB"}` : "Idle";
    document.getElementById("scanStatus").textContent = status;
    document.getElementById("scanStatusAdmin").textContent = status;

    // Update USB message
    let msg, cls;
    if (s.scanning) {
      msg = "Scanning USB…";
      cls = "usb-message scanning";
    } else if (s.threats_found > 0) {
      msg = `⚠ Threats found (${s.threats_found})`;
      cls = "usb-message threat";
    } else if (s.files_scanned > 0) {
      msg = "✓ USB is clean";
      cls = "usb-message clean";
    } else {
      msg = "No USB detected";
      cls = "usb-message";
    }
    document.getElementById("usbMessage").textContent = msg;
    document.getElementById("usbMessage").className = cls;

    // Update USB device counters
    updateUSBDeviceCounters(s);
  } catch (e) {
    console.error("refreshAll failed:", e);
  }
}

// Update USB device counters in dashboard
function updateUSBDeviceCounters(scanData) {
  try {
    // Get element references
    const connectedEl = document.getElementById("connectedDevices");
    const scanningEl = document.getElementById("scanningDevices");
    const threatsEl = document.getElementById("threatsFound");
    const cleanEl = document.getElementById("cleanDevices");

    if (!connectedEl || !scanningEl || !threatsEl || !cleanEl) {
      console.warn("Device counter elements not found");
      return;
    }

    // Calculate device counts
    const connectedCount = scanData.total_devices ? parseInt(scanData.total_devices) : 0;
    const scanningCount = scanData.scanning ? 1 : 0;
    const threatsCount = scanData.threats_found ? Math.max(parseInt(scanData.threats_found), 0) : 0;
    const cleanCount = Math.max(connectedCount - scanningCount - threatsCount, 0);

    console.log("Device counts:", { connectedCount, scanningCount, threatsCount, cleanCount });

    // Update counter displays with transition effect
    updateCounterValue(connectedEl, connectedCount);
    updateCounterValue(scanningEl, scanningCount);
    updateCounterValue(threatsEl, threatsCount);
    updateCounterValue(cleanEl, cleanCount);

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
    const ready = await ensureEelReady();
    if (!ready) return;
    
    const logs = await eel.get_logs(500)();
    const tbody = document.querySelector("#logTable tbody");
    if (!tbody) return;
    
    tbody.innerHTML = "";

    if (!logs || logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="3" class="empty-state">No logs</td></tr>`;
      lastLogId = 0;
      return;
    }

    // Backend already returns newest first.
    logs.forEach(l => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${escapeHtml(l.timestamp || "N/A")}</td>
        <td><span class="log-type log-${(l.type || "info").toLowerCase()}">${escapeHtml(l.type || "N/A")}</span></td>
        <td>${escapeHtml(l.details || "N/A")}</td>`;
      tbody.appendChild(row);
    });

    // Track highest ID for incremental polling.
    const maxId = Math.max(...logs.map(l => Number(l.id) || 0));
    lastLogId = maxId;
    if (isManual) {
      const btn = document.getElementById("refreshLogsBtn");
      if (btn) {
        btn.classList.add("active");
        setTimeout(() => btn.classList.remove("active"), 250);
      }
    }
  } catch (e) {
    console.error("refreshLogs failed:", e);
  } finally {
    refreshInFlight = false;
  }
}

function startLiveLogRefresh() {
  if (liveLogRefreshInterval) clearInterval(liveLogRefreshInterval);
  // Poll backend every 100ms for new logs
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
  }, 100);
}

function stopLiveLogRefresh() {
  if (liveLogRefreshInterval) clearInterval(liveLogRefreshInterval);
}

// Quarantine functions
async function refreshQuarantine() {
  try {
    const list = await eel.get_quarantine_list()();
    const tbody = document.querySelector("#quarantineTable tbody");
    if (!tbody) return;
    
    tbody.innerHTML = "";

    if (!list || list.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No quarantined files</td></tr>`;
      return;
    }

    list.forEach(i => {
      tbody.innerHTML += `
        <tr>
          <td>${escapeHtml(i.quarantined_at || "N/A")}</td>
          <td>${escapeHtml(i.original_path || "N/A")}</td>
          <td>${escapeHtml(i.reason || "N/A")}</td>
          <td class="actions">
            <button onclick="restoreItem('${escapeHtml(i.filename)}')" class="btn-small">Restore</button>
            <button onclick="deleteItem('${escapeHtml(i.filename)}')" class="btn-small">Delete</button>
          </td>
        </tr>`;
    });
  } catch (e) {
    console.error("refreshQuarantine failed:", e);
  }
}

function restoreItem(f) {
  if (confirm("Restore file?")) {
    eel.restore_quarantine_item(f);
    setTimeout(refreshQuarantine, 500);
  }
}

function deleteItem(f) {
  if (confirm("Delete permanently?")) {
    eel.delete_quarantine_item(f);
    setTimeout(refreshQuarantine, 500);
  }
}

function clearQuarantine() {
  if (confirm("Clear all quarantined files?")) {
    eel.clear_quarantine?.();
    setTimeout(refreshQuarantine, 500);
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
  setInterval(refreshAll, 1000);
}

// Add a JS function notifyFrontend that shows a Toastify popup and expose it to Python via eel.expose
function notifyFrontend(title, message) {
  try {
    const text = title ? `<strong>${title}</strong><br>${message}` : message;
    Toastify({
      node: (function(){
        const wrapper = document.createElement("div");
        wrapper.style.padding = "6px 10px";
        wrapper.innerHTML = text;
        return wrapper;
      })(),
      duration: 6000,
      gravity: "top",
      position: "right",
      close: true,
      stopOnFocus: true,
      style: {
        background: "linear-gradient(90deg, #ef5350, #d32f2f)",
        color: "#fff",
        boxShadow: "0 6px 18px rgba(0,0,0,0.12)",
        borderRadius: "8px",
        padding: "8px 12px"
      }
    }).showToast();
  } catch (e) {
    console.error("notifyFrontend error:", e);
  }
}

// Add: show a Toastify notification from Python
function notifyFrontend(title, message) {
  try {
    const content = document.createElement("div");
    content.style.lineHeight = "1.2";
    content.innerHTML = title ? `<strong>${escapeHtml(title)}</strong><br>${escapeHtml(message)}` : escapeHtml(message);

    Toastify({
      node: content,
      duration: 6000,
      gravity: "top",
      position: "right",
      close: true,
      stopOnFocus: true,
      style: {
        background: "linear-gradient(90deg, #343a40, #212529)",
        color: "#fff",
        boxShadow: "0 6px 18px rgba(0,0,0,0.12)",
        borderRadius: "8px",
        padding: "8px 12px"
      }
    }).showToast();
  } catch (e) {
    console.error("notifyFrontend error:", e);
  }
}

// Add: show a Toastify notification from Python with severity levels
function notifyFrontend(title, message, level = "info") {
  try {
    const content = document.createElement("div");
    content.style.lineHeight = "1.15";
    content.style.display = "flex";
    content.style.flexDirection = "row";
    content.style.gap = "10px";
    content.style.alignItems = "center";

    // Icon
    const icon = document.createElement("div");
    icon.style.flex = "0 0 auto";
    icon.style.display = "flex";
    icon.style.alignItems = "center";
    icon.style.justifyContent = "center";
    if (level === "danger") {
      icon.innerHTML = '<i class="fas fa-exclamation-triangle" style="font-size:22px;color:#fff"></i>';
    } else if (level === "warning") {
      icon.innerHTML = '<i class="fas fa-exclamation-circle" style="font-size:20px;color:#fff"></i>';
    } else if (level === "success") {
      icon.innerHTML = '<i class="fas fa-check-circle" style="font-size:20px;color:#fff"></i>';
    } else {
      icon.innerHTML = '<i class="fas fa-info-circle" style="font-size:18px;color:#fff"></i>';
    }

    const textWrap = document.createElement("div");
    textWrap.style.display = "flex";
    textWrap.style.flexDirection = "column";
    textWrap.style.gap = "6px";

    const titleEl = document.createElement("div");
    titleEl.innerHTML = escapeHtml(title || "");
    titleEl.style.fontWeight = "800";
    titleEl.style.fontSize = (level === "danger" ? "1.05rem" : "0.95rem");
    titleEl.style.letterSpacing = "0.2px";

    const msgEl = document.createElement("div");
    msgEl.innerHTML = escapeHtml(message || "");
    msgEl.style.fontSize = (level === "danger" ? "0.95rem" : "0.85rem");

    textWrap.appendChild(titleEl);
    textWrap.appendChild(msgEl);
    content.appendChild(icon);
    content.appendChild(textWrap);

    let style = {
      color: "#fff",
      boxShadow: "0 8px 30px rgba(0,0,0,0.18)",
      borderRadius: "10px",
      padding: "12px 14px",
      maxWidth: "520px"
    };

    let duration = 6000;

    if (level === "danger") {
      style.background = "linear-gradient(90deg, #ff416c 0%, #ff4b2b 100%)";
      style.border = "2px solid rgba(255,255,255,0.12)";
      duration = 14000;
      // Emphasize size for danger
      titleEl.style.fontSize = "1.15rem";
      msgEl.style.fontSize = "1rem";
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
