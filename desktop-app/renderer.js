/**
 * Renderer process for Koba desktop app
 */

const btnToggle = document.getElementById('btn-toggle');
const btnDashboard = document.getElementById('btn-dashboard');
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');

// Update banner elements
const updateBanner = document.getElementById('update-banner');
const updateText = document.getElementById('update-text');
const btnUpdate = document.getElementById('btn-update');
const btnDismiss = document.getElementById('btn-dismiss');

let isRunning = false;

/**
 * Update UI based on status
 */
function updateUI(running, statusMsg) {
  isRunning = running;

  statusDot.className = 'status-dot';
  if (running) {
    statusDot.classList.add('running');
    statusText.textContent = statusMsg || 'Running';
    btnToggle.textContent = 'Stop Koba';
    btnDashboard.disabled = false;
  } else if (statusMsg && statusMsg.includes('Starting')) {
    statusDot.classList.add('starting');
    statusText.textContent = statusMsg;
    btnToggle.textContent = 'Starting...';
    btnDashboard.disabled = true;
  } else {
    statusText.textContent = statusMsg || 'Stopped';
    btnToggle.textContent = 'Start Koba';
    btnDashboard.disabled = true;
  }

  btnToggle.disabled = false;
}

/**
 * Show the update banner
 */
function showUpdateBanner(message, className) {
  updateBanner.style.display = 'flex';
  updateBanner.className = 'update-banner' + (className ? ' ' + className : '');
  updateText.textContent = message;
}

/**
 * Hide the update banner
 */
function hideUpdateBanner() {
  updateBanner.style.display = 'none';
}

/**
 * Initialize
 */
async function init() {
  try {
    const status = await window.koba.getStatus();
    updateUI(status.running, status.running ? 'Running' : 'Stopped');

    document.getElementById('dashboard-url').textContent = `http://localhost:${status.port}`;
    document.getElementById('api-url').textContent = `http://localhost:${status.apiPort}`;

    // Check if there's a pending update
    const updateStatus = await window.koba.getUpdateStatus();
    if (updateStatus.available) {
      showUpdateBanner('New update available! Click to install.');
      btnUpdate.style.display = '';
      btnDismiss.style.display = '';
    }
  } catch (error) {
    statusText.textContent = 'Error: ' + error.message;
  }
}

/**
 * Toggle start/stop
 */
let isBusy = false;
btnToggle.addEventListener('click', async () => {
  if (isBusy) return;
  isBusy = true;
  btnToggle.disabled = true;
  try {
    if (isRunning) {
      statusDot.className = 'status-dot starting';
      statusText.textContent = 'Stopping...';
      await window.koba.stopKoba();
      updateUI(false, 'Stopped');
    } else {
      statusDot.className = 'status-dot starting';
      statusText.textContent = 'Starting...';
      await window.koba.startKoba();
      updateUI(true, 'Running');
    }
  } catch (error) {
    statusDot.className = 'status-dot error';
    statusText.textContent = 'Error: ' + (error.message || 'Unknown error');
    btnToggle.disabled = false;
  } finally {
    isBusy = false;
  }
});

/**
 * Open dashboard
 */
btnDashboard.addEventListener('click', () => {
  window.koba.openDashboard();
});

/**
 * Update banner interactions
 */
btnUpdate.addEventListener('click', async () => {
  btnUpdate.disabled = true;
  btnUpdate.textContent = 'Updating...';
  try {
    await window.koba.applyUpdate();
  } catch (err) {
    updateText.textContent = 'Update failed: ' + (err.message || 'Unknown error');
    btnUpdate.disabled = false;
    btnUpdate.textContent = 'Retry';
  }
});

btnDismiss.addEventListener('click', async () => {
  hideUpdateBanner();
  await window.koba.dismissUpdate();
});

/**
 * Listen for status updates from main process
 */
window.koba.onStatusUpdate((status) => {
  if (status === 'Running') {
    updateUI(true, status);
  } else if (status === 'Stopped') {
    updateUI(false, status);
  } else if (status.toLowerCase().includes('error') || status.toLowerCase().includes('failed')) {
    statusDot.className = 'status-dot error';
    statusText.textContent = status;
    btnToggle.disabled = false;
    isBusy = false;
  } else {
    statusDot.className = 'status-dot starting';
    statusText.textContent = status;
  }
});

/**
 * Listen for update events
 */
window.koba.onUpdateChecking(() => {
  showUpdateBanner('Checking for updates...', 'checking');
  btnUpdate.style.display = 'none';
  btnDismiss.style.display = 'none';
});

window.koba.onUpdateAvailable((info) => {
  showUpdateBanner('New update available! Restart to apply.');
  btnUpdate.style.display = '';
  btnUpdate.disabled = false;
  btnUpdate.textContent = 'Update Now';
  btnDismiss.style.display = '';
});

window.koba.onUpdateNotAvailable(() => {
  hideUpdateBanner();
});

window.koba.onUpdateProgress((data) => {
  if (data.status) {
    updateText.textContent = 'Downloading: ' + data.status;
  }
});

window.koba.onUpdateApplying(() => {
  showUpdateBanner('Applying update... Restarting Koba...', 'applying');
  btnUpdate.style.display = 'none';
  btnDismiss.style.display = 'none';
});

window.koba.onUpdateApplied(() => {
  showUpdateBanner('Update complete! Running latest version.', 'applying');
  btnDismiss.style.display = '';
  setTimeout(hideUpdateBanner, 5000);
});

window.koba.onUpdateError((msg) => {
  // Only show error if banner is already visible
  if (updateBanner.style.display !== 'none') {
    updateText.textContent = 'Update check failed';
    btnDismiss.style.display = '';
    setTimeout(hideUpdateBanner, 3000);
  }
});

// Initialize on load
init();
