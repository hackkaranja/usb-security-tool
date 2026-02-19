// =========================
//  SETTINGS MODULE
// =========================

async function loadSettings() {
  try {
    let s;
    if (typeof eel.get_settings === "function") {
      s = await eel.get_settings()();
    } else if (typeof eel.get_config === "function") {
      s = await eel.get_config()();
    } else {
      return;
    }
    document.getElementById("autoScanToggle").checked = !!s.auto_scan;
    document.getElementById("yaraToggle").checked = !!s.enable_yara;
  } catch (e) {
    console.error("loadSettings failed", e);
  }
}

async function saveSettings() {
  const status = document.getElementById("settingsStatus");
  status.textContent = "Saving...";
  status.style.color = "";

  try {
    const payload = {
      auto_scan: document.getElementById("autoScanToggle").checked,
      enable_yara: document.getElementById("yaraToggle").checked
    };

    if (typeof eel.save_settings === "function") {
      await eel.save_settings(payload)();
    } else if (typeof eel.save_config === "function") {
      await eel.save_config(payload)();
    }

    status.textContent = "✓ Saved";
    status.style.color = "#28a745";
  } catch (e) {
    status.textContent = "✗ Failed";
    status.style.color = "#dc3545";
    console.error(e);
  }
}

async function updateYaraRules() {
  const btn = document.getElementById("yaraUpdateBtn");
  const status = document.getElementById("yaraStatus");
  const progress = document.getElementById("yaraProgress");
  const fill = document.getElementById("yaraProgressFill");
  const text = document.getElementById("yaraProgressText");

  btn.disabled = true;
  status.textContent = "Checking rules location...";
  status.style.color = "";
  progress.classList.remove("hidden");
  fill.style.width = "0%";
  text.textContent = "0%";

  try {
    // Step 1: Check rules directory
    for (let i = 0; i <= 20; i += 5) {
      fill.style.width = `${i}%`;
      text.textContent = `${i}%`;
      await new Promise(r => setTimeout(r, 100));
    }
    status.textContent = "Validating rules...";

    // Step 2: Validate
    for (let i = 20; i <= 50; i += 5) {
      fill.style.width = `${i}%`;
      text.textContent = `${i}%`;
      await new Promise(r => setTimeout(r, 100));
    }
    status.textContent = "Loading rules...";

    // Step 3: Load rules
    for (let i = 50; i <= 80; i += 5) {
      fill.style.width = `${i}%`;
      text.textContent = `${i}%`;
      await new Promise(r => setTimeout(r, 100));
    }

    // Call backend to update/load rules
    const r = await eel.reload_yara_rules()();

    fill.style.width = "100%";
    text.textContent = "100%";

    if (r?.success) {
      status.textContent = `✓ Loaded ${r.count || 0} YARA rules`;
      status.style.color = "#28a745";
      console.log("YARA rules loaded successfully:", r);
      setTimeout(() => progress.classList.add("hidden"), 1500);
    } else if (r?.error) {
      throw new Error(r.error);
    } else {
      throw new Error("Unknown error loading rules");
    }
  } catch (e) {
    status.textContent = `✗ Error: ${e.message}`;
    status.style.color = "#dc3545";
    fill.style.width = "0%";
    text.textContent = "Failed";
    console.error("YARA update error:", e);
  } finally {
    btn.disabled = false;
  }
}

async function changePassword() {
  const status = document.getElementById("passwordStatus");
  const newP = document.getElementById("newPassword").value;
  const confirmP = document.getElementById("confirmPassword").value;

  if (!newP || !confirmP) {
    status.textContent = "Enter password";
    status.style.color = "#dc3545";
    return;
  }

  if (newP !== confirmP) {
    status.textContent = "Passwords don't match";
    status.style.color = "#dc3545";
    return;
  }

  if (newP.length < 6) {
    status.textContent = "Min 6 characters";
    status.style.color = "#dc3545";
    return;
  }

  status.textContent = "Updating...";
  status.style.color = "";

  try {
    const r = await eel.update_admin_password(newP)();
    if (r?.success) {
      status.textContent = "✓ Updated";
      status.style.color = "#28a745";
      document.getElementById("newPassword").value = "";
      document.getElementById("confirmPassword").value = "";
    } else {
      throw new Error(r?.message || "Update failed");
    }
  } catch (e) {
    status.textContent = `✗ ${e.message}`;
    status.style.color = "#dc3545";
    console.error(e);
  }
}
