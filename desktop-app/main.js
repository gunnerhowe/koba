/**
 * Koba Desktop Application
 *
 * Electron wrapper that:
 * - Manages Docker container lifecycle
 * - Provides system tray icon
 * - Displays dashboard in-app (no browser needed)
 * - Auto-starts on system boot (optional)
 */

const { app, BrowserWindow, Tray, Menu, shell, dialog, nativeImage, ipcMain } = require('electron');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { exec } = require('child_process');
const Store = require('electron-store');
const Docker = require('dockerode');

// Prevent multiple instances - only one Koba can run at a time
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    // Someone tried to open a second instance - focus our existing windows
    if (dashboardWindow) {
      if (dashboardWindow.isMinimized()) dashboardWindow.restore();
      dashboardWindow.show();
      dashboardWindow.focus();
    } else if (controlWindow) {
      if (controlWindow.isMinimized()) controlWindow.restore();
      controlWindow.show();
      controlWindow.focus();
    }
  });
}

/**
 * Stop any existing Koba Docker containers that may be holding our ports.
 * This is safer than blindly killing any process on the port.
 */
async function killPortProcesses() {
  try {
    // Only stop our own Docker container, not arbitrary processes
    const containers = await docker.listContainers({ all: true });
    const kobaContainer = containers.find(c => c.Names.includes(`/${CONTAINER_NAME}`));
    if (kobaContainer && kobaContainer.State === 'running') {
      const container = docker.getContainer(kobaContainer.Id);
      await container.stop().catch(() => {});
    }
  } catch (e) {
    console.log('Could not stop stale Koba container:', e.message);
  }
}

// Configuration store
const store = new Store({
  defaults: {
    autoStart: true,
    openOnStart: true,
    port: 3000,
    apiPort: 8000,
    registryImage: 'kobaai/koba:latest',
    autoCheckUpdates: true,
    lastUpdateCheck: 0,
  }
});

// Docker client
const docker = new Docker();

// Generate a stable JWT secret per installation (persisted in electron-store)
function getJwtSecret() {
  let secret = store.get('jwtSecret');
  if (!secret) {
    secret = crypto.randomBytes(32).toString('hex');
    store.set('jwtSecret', secret);
  }
  return secret;
}

// State
let controlWindow = null;
let dashboardWindow = null;
let tray = null;
let containerRunning = false;
let containerId = null;
let updateAvailable = false;
let updateInfo = null;
let isApplyingUpdate = false;

// Constants
const CONTAINER_NAME = 'koba-server';
const IMAGE_NAME = 'koba:latest';
function getDashboardUrl() { return `http://localhost:${store.get('port')}`; }
function getApiUrl() { return `http://localhost:${store.get('apiPort')}`; }

/**
 * Create the control panel window (small status/management window)
 */
function createControlWindow() {
  controlWindow = new BrowserWindow({
    width: 540,
    height: 520,
    resizable: true,
    minWidth: 480,
    minHeight: 460,
    frame: true,
    icon: path.join(__dirname, 'assets', 'icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
    }
  });

  controlWindow.loadFile(path.join(__dirname, 'index.html'));

  controlWindow.on('close', (event) => {
    if (!app.isQuitting) {
      event.preventDefault();
      controlWindow.hide();
    }
  });

  controlWindow.on('closed', () => {
    controlWindow = null;
  });
}

/**
 * Create or show the dashboard window (full-size, loads the web app)
 */
function openDashboard() {
  if (dashboardWindow) {
    dashboardWindow.show();
    dashboardWindow.focus();
    return;
  }

  dashboardWindow = new BrowserWindow({
    width: 1280,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    resizable: true,
    frame: true,
    title: 'Koba - AI Governance Platform',
    icon: path.join(__dirname, 'assets', 'icon.png'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'dashboard-preload.js'),
    }
  });

  // Load root - auth system will redirect to /login if needed, or restore session
  dashboardWindow.loadURL(getDashboardUrl());

  // Handle navigation within the app - keep all localhost links in-app
  dashboardWindow.webContents.setWindowOpenHandler(({ url }) => {
    const dashboardPort = store.get('port');
    const apiPort = store.get('apiPort');
    const allowedOrigins = [
      `http://localhost:${dashboardPort}`,
      `http://localhost:${apiPort}`,
    ];
    const isAllowed = allowedOrigins.some(origin => url.startsWith(origin));
    // Keep allowed URLs in the same window
    if (isAllowed) {
      dashboardWindow.loadURL(url);
      return { action: 'deny' };
    }
    // Open external links in the browser
    shell.openExternal(url);
    return { action: 'deny' };
  });

  // Intercept link clicks that would open in a new window
  dashboardWindow.webContents.on('will-navigate', (event, url) => {
    const dashboardPort = store.get('port');
    const apiPort = store.get('apiPort');
    const allowedOrigins = [
      `http://localhost:${dashboardPort}`,
      `http://localhost:${apiPort}`,
    ];
    const isAllowed = allowedOrigins.some(origin => url.startsWith(origin));
    // Allow navigation within allowed origins
    if (isAllowed) {
      return;
    }
    // Open external URLs in the default browser
    event.preventDefault();
    shell.openExternal(url);
  });

  dashboardWindow.on('closed', () => {
    dashboardWindow = null;
  });
}

/**
 * Create system tray
 */
function createTray() {
  const iconPath = path.join(__dirname, 'assets', 'tray-icon.png');
  const icon = nativeImage.createFromPath(iconPath);

  tray = new Tray(icon.resize({ width: 16, height: 16 }));

  updateTrayMenu();

  tray.on('click', () => {
    if (containerRunning) {
      openDashboard();
    } else if (controlWindow) {
      controlWindow.show();
      controlWindow.focus();
    }
  });

  tray.setToolTip('Koba AI Governance');
}

/**
 * Update tray menu based on container state
 */
function updateTrayMenu() {
  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Open Dashboard',
      click: () => openDashboard(),
      enabled: containerRunning,
    },
    { type: 'separator' },
    {
      label: containerRunning ? 'Stop Koba' : 'Start Koba',
      click: () => containerRunning ? stopContainer() : startContainer(),
    },
    {
      label: 'Restart',
      click: () => restartContainer(),
      enabled: containerRunning,
    },
    { type: 'separator' },
    {
      label: 'View Logs',
      click: () => viewLogs(),
      enabled: containerRunning,
    },
    { type: 'separator' },
    {
      label: 'Control Panel',
      click: () => {
        if (controlWindow) {
          controlWindow.show();
          controlWindow.focus();
        } else {
          createControlWindow();
        }
      },
    },
    { type: 'separator' },
    {
      label: 'Quit Koba',
      click: () => {
        app.isQuitting = true;
        stopContainer()
          .then(() => killPortProcesses())
          .then(() => app.quit());
      },
    },
  ]);

  tray.setContextMenu(contextMenu);
}

/**
 * Check if Docker is available
 */
async function checkDocker() {
  try {
    await docker.ping();
    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Build or pull the Koba image
 */
async function ensureImage() {
  try {
    await docker.getImage(IMAGE_NAME).inspect();
    console.log('Koba image found');
    return true;
  } catch (error) {
    console.log('Koba image not found, building...');
    updateStatus('Pulling Koba image (this may take a few minutes)...');

    try {
      await docker.pull(IMAGE_NAME);
      return true;
    } catch (pullError) {
      console.error('Failed to pull image:', pullError);
      return false;
    }
  }
}

/**
 * Start the Koba container
 */
async function startContainer() {
  updateStatus('Starting Koba...');

  try {
    // Check for existing container
    const containers = await docker.listContainers({ all: true });
    const existing = containers.find(c => c.Names.includes(`/${CONTAINER_NAME}`));

    if (existing) {
      const container = docker.getContainer(existing.Id);

      // Check if container has the CORRECT JWT_SECRET (must match electron-store)
      const info = await container.inspect();
      const envVars = info.Config.Env || [];
      const expectedSecret = getJwtSecret();
      const hasCorrectSecret = envVars.some(e => e === `JWT_SECRET=${expectedSecret}`);
      if (!hasCorrectSecret) {
        console.log('Container has wrong or missing JWT_SECRET, recreating...');
        if (existing.State === 'running') {
          await container.stop().catch(() => {});
        }
        await container.remove().catch(() => {});
        // Fall through to create new container below
      } else if (existing.State === 'running') {
        containerId = existing.Id;
        containerRunning = true;
        updateStatus('Running');
        updateTrayMenu();
        await waitForServices();
        if (store.get('openOnStart')) {
          openDashboard();
        }
        return;
      } else {
        // Start existing container (has JWT_SECRET, just stopped)
        await container.start();
        containerId = existing.Id;
      }
    }

    if (!containerId) {
      // Create new container
      const container = await docker.createContainer({
        name: CONTAINER_NAME,
        Image: IMAGE_NAME,
        ExposedPorts: {
          '3000/tcp': {},
          '8000/tcp': {},
        },
        HostConfig: {
          PortBindings: {
            '3000/tcp': [{ HostPort: String(store.get('port')) }],
            '8000/tcp': [{ HostPort: String(store.get('apiPort')) }],
          },
          Binds: [
            `koba-data:/app/data`,
          ],
          RestartPolicy: {
            Name: 'unless-stopped',
          },
        },
        Env: [
          'VACP_ENV=production',
          'NODE_ENV=production',
          'VACP_ADMIN_PASSWORD=admin123',
          `JWT_SECRET=${getJwtSecret()}`,
          'VACP_STORAGE_PATH=/app/data',
        ],
      });

      await container.start();
      containerId = container.id;
    }

    containerRunning = true;
    updateStatus('Running');
    updateTrayMenu();

    // Wait for services to be ready
    await waitForServices();

    // Open dashboard in-app if configured
    if (store.get('openOnStart')) {
      openDashboard();
    }

  } catch (error) {
    console.error('Failed to start container:', error);
    updateStatus('Error: ' + error.message);
    containerRunning = false;
    updateTrayMenu();

    dialog.showErrorBox('Koba Error', `Failed to start Koba: ${error.message}`);
  }
}

/**
 * Stop the Koba container
 */
async function stopContainer() {
  if (!containerId) return;

  updateStatus('Stopping...');

  try {
    const container = docker.getContainer(containerId);
    await container.stop();
    containerRunning = false;
    containerId = null;
    updateStatus('Stopped');
    updateTrayMenu();
  } catch (error) {
    console.error('Failed to stop container:', error);
  }
}

/**
 * Restart the container
 */
async function restartContainer() {
  await stopContainer();
  await new Promise(r => setTimeout(r, 2000));
  await startContainer();
}

/**
 * Wait for services to be ready
 */
async function waitForServices() {
  const maxAttempts = 30;
  let attempts = 0;

  while (attempts < maxAttempts) {
    try {
      await new Promise((resolve, reject) => {
        const req = http.get(`${getApiUrl()}/health`, (res) => {
          if (res.statusCode === 200) resolve();
          else reject(new Error(`Status: ${res.statusCode}`));
        });
        req.on('error', reject);
        req.setTimeout(1000, () => {
          req.destroy();
          reject(new Error('Health check timeout'));
        });
      });
      console.log('Services ready');
      return;
    } catch (error) {
      attempts++;
      await new Promise(r => setTimeout(r, 1000));
    }
  }

  console.warn('Services may not be fully ready');
}

/**
 * View container logs
 */
async function viewLogs() {
  if (!containerId) return;

  try {
    const container = docker.getContainer(containerId);
    const logs = await container.logs({
      stdout: true,
      stderr: true,
      tail: 100,
    });

    const logWindow = new BrowserWindow({
      width: 800,
      height: 600,
      title: 'Koba Logs',
      icon: path.join(__dirname, 'assets', 'icon.png'),
      webPreferences: {
        nodeIntegration: false,
        contextIsolation: true,
      }
    });

    const logHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { background: #0a0a0f; color: #f0f0f5; font-family: monospace; padding: 20px; margin: 0; }
          pre { white-space: pre-wrap; word-wrap: break-word; font-size: 12px; line-height: 1.5; }
        </style>
      </head>
      <body>
        <pre>${logs.toString()
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#039;')}</pre>
      </body>
      </html>
    `;

    logWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(logHtml)}`);
  } catch (error) {
    console.error('Failed to get logs:', error);
  }
}

/**
 * Update status display
 */
function updateStatus(status) {
  console.log('Status:', status);
  if (controlWindow) {
    controlWindow.webContents.send('status-update', status);
  }
}

/**
 * Send message to control window
 */
function sendToControlWindow(channel, data) {
  if (controlWindow && !controlWindow.isDestroyed()) {
    controlWindow.webContents.send(channel, data);
  }
}

/**
 * Check Docker registry for a newer image
 */
async function checkForImageUpdate(silent = false) {
  const registryImage = store.get('registryImage');
  if (!registryImage) {
    console.log('[Update] No registry image configured, skipping');
    return false;
  }

  console.log('[Update] Checking for updates from', registryImage);
  if (!silent) {
    sendToControlWindow('update-checking');
  }

  try {
    // Get current local image ID
    let localImageId;
    try {
      const imageInfo = await docker.getImage(IMAGE_NAME).inspect();
      localImageId = imageInfo.Id;
    } catch {
      console.log('[Update] No local image found');
      return false;
    }

    // Pull from registry (checks manifest, downloads only changed layers)
    await new Promise((resolve, reject) => {
      docker.pull(registryImage, (err, stream) => {
        if (err) return reject(err);
        docker.modem.followProgress(stream,
          (err, output) => err ? reject(err) : resolve(output),
          (event) => {
            if (event.status) {
              sendToControlWindow('update-progress', { status: event.status });
            }
          }
        );
      });
    });

    // Compare pulled image with local
    const newImageInfo = await docker.getImage(registryImage).inspect();

    if (newImageInfo.Id !== localImageId) {
      // Tag the new image as our local image name
      await docker.getImage(registryImage).tag({ repo: 'koba', tag: 'latest' });

      updateAvailable = true;
      updateInfo = {
        currentId: localImageId.substring(7, 19),
        newId: newImageInfo.Id.substring(7, 19),
      };

      console.log('[Update] New version available!', updateInfo);
      sendToControlWindow('update-available', updateInfo);
      store.set('lastUpdateCheck', Date.now());
      return true;
    }

    console.log('[Update] Already up to date');
    sendToControlWindow('update-not-available');
    store.set('lastUpdateCheck', Date.now());
    return false;
  } catch (err) {
    console.log('[Update] Check failed:', err.message);
    if (!silent) {
      sendToControlWindow('update-error', err.message);
    }
    return false;
  }
}

/**
 * Apply a downloaded image update by restarting the container
 */
async function applyImageUpdate() {
  if (!updateAvailable || isApplyingUpdate) return;
  isApplyingUpdate = true;

  try {
    sendToControlWindow('update-applying');
    updateStatus('Applying update...');

    // Stop and remove the old container so it recreates with the new image
    if (containerId) {
      const container = docker.getContainer(containerId);
      if (containerRunning) {
        await container.stop().catch(() => {});
      }
      await container.remove().catch(() => {});
      containerRunning = false;
      containerId = null;
    }

    updateAvailable = false;
    updateInfo = null;

    // Start fresh container with the updated image
    await startContainer();

    sendToControlWindow('update-applied');
  } catch (err) {
    console.error('[Update] Apply failed:', err);
    sendToControlWindow('update-error', 'Failed to apply update: ' + err.message);
    updateStatus('Update failed: ' + err.message);
  } finally {
    isApplyingUpdate = false;
  }
}

/**
 * App lifecycle
 */
app.whenReady().then(async () => {
  const { session } = require('electron');
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': ["default-src 'self' http://localhost:*; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: http://localhost:*; connect-src 'self' http://localhost:* ws://localhost:*"],
      },
    });
  });

  // Kill any stale processes on our ports before starting
  await killPortProcesses();

  // Check Docker
  const dockerAvailable = await checkDocker();
  if (!dockerAvailable) {
    dialog.showErrorBox(
      'Docker Required',
      'Koba requires Docker to be installed and running.\n\nPlease install Docker Desktop and try again.'
    );
    app.quit();
    return;
  }

  // Ensure image exists
  const imageReady = await ensureImage();
  if (!imageReady) {
    dialog.showErrorBox(
      'Image Not Found',
      'Could not find or build the Koba image.\n\nPlease check your installation.'
    );
    app.quit();
    return;
  }

  createTray();
  createControlWindow();

  // Auto-start container
  if (store.get('autoStart')) {
    await startContainer();
  }

  // Check for Docker image updates in background
  if (store.get('autoCheckUpdates') && store.get('registryImage')) {
    const lastCheck = store.get('lastUpdateCheck');
    const ONE_DAY = 24 * 60 * 60 * 1000;
    if (Date.now() - lastCheck > ONE_DAY) {
      setTimeout(() => checkForImageUpdate(true), 5000);
    }
  }

  // Check for Electron shell updates (if electron-updater is installed)
  try {
    const { autoUpdater } = require('electron-updater');
    autoUpdater.autoDownload = true;
    autoUpdater.autoInstallOnAppQuit = true;
    autoUpdater.checkForUpdatesAndNotify().catch(() => {});
  } catch {
    // electron-updater not available, skip shell updates
  }

  // macOS: Re-create window when dock icon is clicked
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createControlWindow();
    }
  });
});

app.on('window-all-closed', () => {
  // Keep running in tray on all platforms
});

// Clean up on quit
let isCleaningUp = false;
app.on('before-quit', (event) => {
  app.isQuitting = true;

  // Guard against re-entrancy: if we already cleaned up, let the quit proceed
  if (isCleaningUp) return;

  // If the container is running or ports may be occupied, perform async cleanup
  if (containerRunning && containerId) {
    event.preventDefault();
    isCleaningUp = true;
    stopContainer()
      .then(() => killPortProcesses())
      .catch((err) => console.error('Cleanup error:', err))
      .finally(() => {
        app.isQuitting = true;
        app.quit();
      });
  } else {
    // No container running, but still kill any orphaned port processes synchronously-ish
    event.preventDefault();
    isCleaningUp = true;
    killPortProcesses()
      .catch((err) => console.error('Port cleanup error:', err))
      .finally(() => {
        app.isQuitting = true;
        app.quit();
      });
  }
});

// Handle IPC messages from renderer
ipcMain.handle('get-status', () => {
  return {
    running: containerRunning,
    port: store.get('port'),
    apiPort: store.get('apiPort'),
    adminPassword: store.get('_generatedAdminPassword') || null,
  };
});

ipcMain.handle('start-koba', () => startContainer());
ipcMain.handle('stop-koba', () => stopContainer());
ipcMain.handle('open-dashboard', () => openDashboard());
ipcMain.handle('get-settings', () => store.store);
const ALLOWED_SETTINGS = {
  autoStart: 'boolean',
  openOnStart: 'boolean',
  port: 'number',
  apiPort: 'number',
};

ipcMain.handle('set-settings', (event, settings) => {
  Object.entries(settings).forEach(([key, value]) => {
    if (key in ALLOWED_SETTINGS && typeof value === ALLOWED_SETTINGS[key]) {
      store.set(key, value);
    }
  });
  return store.store;
});

// Update system IPC
ipcMain.handle('check-for-update', () => checkForImageUpdate());
ipcMain.handle('apply-update', () => applyImageUpdate());
ipcMain.handle('dismiss-update', () => {
  updateAvailable = false;
  updateInfo = null;
});
ipcMain.handle('get-update-status', () => ({
  available: updateAvailable,
  info: updateInfo,
  applying: isApplyingUpdate,
}));

// Auth state persistence (electron-store backed, survives localStorage clearing)
ipcMain.handle('get-auth-state', () => {
  return store.get('authState') || null;
});

ipcMain.handle('set-auth-state', (event, state) => {
  if (state && typeof state === 'object' && state.token) {
    store.set('authState', state);
  }
});

ipcMain.handle('clear-auth-state', () => {
  store.delete('authState');
});
