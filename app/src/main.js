const { invoke } = window.__TAURI__.core;

let daemonIndicatorEl;
let daemonStatusTextEl;
let btnStartEl;
let btnStopEl;
let statBrowsersEl;
let statHistoryEl;
let statLastSyncEl;
let devicesContainerEl;
let logsPanelEl;
let btnClearLogsEl;

let localClearedLogs = false;

async function fetchStats() {
  try {
    const stats = await invoke("get_stats");
    
    // Update daemon status UI
    if (stats.daemon_status === "Running") {
      daemonIndicatorEl.className = "dot running";
      daemonStatusTextEl.textContent = "Running";
      btnStartEl.disabled = true;
      btnStopEl.disabled = false;
    } else {
      daemonIndicatorEl.className = "dot stopped";
      daemonStatusTextEl.textContent = "Stopped";
      btnStartEl.disabled = false;
      btnStopEl.disabled = true;
    }

    // Update metrics
    statBrowsersEl.textContent = stats.browser_count;
    statHistoryEl.textContent = stats.history_count;

    if (stats.last_sync) {
      const date = new Date(stats.last_sync);
      statLastSyncEl.textContent = date.toLocaleTimeString() + " " + date.toLocaleDateString();
    } else {
      statLastSyncEl.textContent = "Never";
    }

    // Update devices list
    if (stats.devices && stats.devices.length > 0) {
      devicesContainerEl.innerHTML = stats.devices
        .map(dev => {
          const seenDate = new Date(dev.last_seen);
          const seenStr = seenDate.toLocaleTimeString();
          return `
            <div class="device-item">
              <div class="device-meta">
                <span class="device-name">${dev.name}</span>
                <span class="device-id">${dev.id.substring(0, 12)}...</span>
              </div>
              <span class="device-seen">Seen: ${seenStr}</span>
            </div>
          `;
        })
        .join("");
    } else {
      devicesContainerEl.innerHTML = `<p class="empty-msg">No devices connected.</p>`;
    }
  } catch (err) {
    console.error("Failed to fetch stats", err);
  }
}

async function fetchLogs() {
  if (localClearedLogs) return;
  try {
    const logs = await invoke("get_daemon_logs");
    if (logs && logs.length > 0) {
      logsPanelEl.textContent = logs.join("\n");
      // Scroll to bottom
      logsPanelEl.scrollTop = logsPanelEl.scrollHeight;
    } else {
      logsPanelEl.textContent = "No logs generated yet.";
    }
  } catch (err) {
    console.error("Failed to fetch logs", err);
  }
}

async function startDaemon() {
  try {
    await invoke("control_daemon", { action: "start" });
    localClearedLogs = false;
    await fetchStats();
    await fetchLogs();
  } catch (err) {
    alert("Error starting daemon: " + err);
  }
}

async function stopDaemon() {
  try {
    await invoke("control_daemon", { action: "stop" });
    await fetchStats();
  } catch (err) {
    alert("Error stopping daemon: " + err);
  }
}

window.addEventListener("DOMContentLoaded", () => {
  // Query elements
  daemonIndicatorEl = document.querySelector("#daemon-indicator");
  daemonStatusTextEl = document.querySelector("#daemon-status-text");
  btnStartEl = document.querySelector("#btn-start");
  btnStopEl = document.querySelector("#btn-stop");
  statBrowsersEl = document.querySelector("#stat-browsers");
  statHistoryEl = document.querySelector("#stat-history");
  statLastSyncEl = document.querySelector("#stat-last-sync");
  devicesContainerEl = document.querySelector("#devices-container");
  logsPanelEl = document.querySelector("#logs-panel");
  btnClearLogsEl = document.querySelector("#btn-clear-logs");

  // Event Listeners
  btnStartEl.addEventListener("click", startDaemon);
  btnStopEl.addEventListener("click", stopDaemon);
  btnClearLogsEl.addEventListener("click", () => {
    logsPanelEl.textContent = "Logs cleared.";
    localClearedLogs = true;
  });

  // Initial fetch and start interval loops
  fetchStats();
  fetchLogs();

  setInterval(fetchStats, 1000);
  setInterval(fetchLogs, 1500);
});
