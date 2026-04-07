// sidepanel/sidepanel.js — Side Panel logic

const STATUS_ICONS = {
  pending: '',
  running: '',
  completed: '\u2713',  // ✓
  failed: '\u2717',     // ✗
  stopped: '\u25A0',    // ■
};

const logArea = document.getElementById('log-area');
const displayOauthUrl = document.getElementById('display-oauth-url');
const displayLocalhostUrl = document.getElementById('display-localhost-url');
const displayStatus = document.getElementById('display-status');
const statusBar = document.getElementById('status-bar');
const inputEmail = document.getElementById('input-email');
const inputPassword = document.getElementById('input-password');
const btnFetchEmail = document.getElementById('btn-fetch-email');
const btnTogglePassword = document.getElementById('btn-toggle-password');
const btnStop = document.getElementById('btn-stop');
const btnReset = document.getElementById('btn-reset');
const stepsProgress = document.getElementById('steps-progress');
const btnAutoRun = document.getElementById('btn-auto-run');
const btnAutoContinue = document.getElementById('btn-auto-continue');
const autoContinueBar = document.getElementById('auto-continue-bar');
const autoContinueHint = document.getElementById('auto-continue-hint');
const btnClearLog = document.getElementById('btn-clear-log');
const inputVpsUrl = document.getElementById('input-vps-url');
const inputRunCount = document.getElementById('input-run-count');
// IMAP mode elements
const selectEmailMode = document.getElementById('select-email-mode');
const imapSection = document.getElementById('imap-section');
const inputImapEmailList = document.getElementById('input-imap-email-list');
const inputImapBridgeHost = document.getElementById('input-imap-bridge-host');
const inputImapBridgePort = document.getElementById('input-imap-bridge-port');
// Proxy elements
const selectProxyType = document.getElementById('select-proxy-type');
const inputProxyHost = document.getElementById('input-proxy-host');
const inputProxyPort = document.getElementById('input-proxy-port');
const proxyHostSep = document.querySelector('.proxy-host-sep');
const proxyAuthSection = document.getElementById('proxy-auth-section');
const inputProxyUser = document.getElementById('input-proxy-user');
const inputProxyPass = document.getElementById('input-proxy-pass');
let autoContinueMode = 'email';

// ============================================================
// Toast Notifications
// ============================================================

const toastContainer = document.getElementById('toast-container');

const TOAST_ICONS = {
  error: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
  warn: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  success: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
  info: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
};

function showToast(message, type = 'error', duration = 4000) {
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `${TOAST_ICONS[type] || ''}<span class="toast-msg">${escapeHtml(message)}</span><button class="toast-close">&times;</button>`;

  toast.querySelector('.toast-close').addEventListener('click', () => dismissToast(toast));
  toastContainer.appendChild(toast);

  if (duration > 0) {
    setTimeout(() => dismissToast(toast), duration);
  }
}

function dismissToast(toast) {
  if (!toast.parentNode) return;
  toast.classList.add('toast-exit');
  toast.addEventListener('animationend', () => toast.remove());
}

// ============================================================
// State Restore on load
// ============================================================

async function restoreState() {
  try {
    const state = await chrome.runtime.sendMessage({ type: 'GET_STATE', source: 'sidepanel' });

    if (state.oauthUrl) {
      displayOauthUrl.textContent = state.oauthUrl;
      displayOauthUrl.classList.add('has-value');
    }
    if (state.localhostUrl) {
      displayLocalhostUrl.textContent = state.localhostUrl;
      displayLocalhostUrl.classList.add('has-value');
    }
    if (state.email) {
      inputEmail.value = state.email;
    }
    syncPasswordField(state);
    if (state.vpsUrl) {
      inputVpsUrl.value = state.vpsUrl;
    }

    // Restore IMAP settings
    if (state.emailMode) {
      selectEmailMode.value = state.emailMode;
      applyEmailModeUI(state.emailMode);
    }
    if (state.imapEmailList && Array.isArray(state.imapEmailList)) {
      inputImapEmailList.value = state.imapEmailList.join('\n');
    }
    if (state.imapBridgeHost) {
      inputImapBridgeHost.value = state.imapBridgeHost;
    }
    if (state.imapBridgePort) {
      inputImapBridgePort.value = state.imapBridgePort;
    }

    // Restore proxy settings
    if (state.proxyType) {
      selectProxyType.value = state.proxyType;
      applyProxyUI(state.proxyType);
    }
    if (state.proxyHost) {
      inputProxyHost.value = state.proxyHost;
    }
    if (state.proxyPort) {
      inputProxyPort.value = state.proxyPort;
    }
    if (state.proxyUser) {
      inputProxyUser.value = state.proxyUser;
    }
    if (state.proxyPass) {
      inputProxyPass.value = state.proxyPass;
    }

    if (state.stepStatuses) {
      for (const [step, status] of Object.entries(state.stepStatuses)) {
        updateStepUI(Number(step), status);
      }
    }

    if (state.logs) {
      for (const entry of state.logs) {
        appendLog(entry);
      }
    }

    updateStatusDisplay(state);
    updateProgressCounter();
  } catch (err) {
    console.error('Failed to restore state:', err);
  }
}

function syncPasswordField(state) {
  inputPassword.value = state.customPassword || state.password || '';
}

function applyEmailModeUI(mode) {
  if (mode === 'imap') {
    imapSection.style.display = '';
    btnFetchEmail.style.display = 'none';
    inputEmail.placeholder = 'Auto-selected from IMAP list';
    inputEmail.readOnly = true;
  } else {
    imapSection.style.display = 'none';
    btnFetchEmail.style.display = '';
    inputEmail.placeholder = 'Auto fetch from Burner Mailbox or paste manually';
    inputEmail.readOnly = false;
  }
}

function applyProxyUI(type) {
  const hasProxy = type && type !== 'none';
  const displayVal = hasProxy ? '' : 'none';
  inputProxyHost.style.display = displayVal;
  inputProxyPort.style.display = displayVal;
  proxyHostSep.style.display = displayVal;
  proxyAuthSection.style.display = displayVal;
}

// ============================================================
// UI Updates
// ============================================================

function updateStepUI(step, status) {
  const statusEl = document.querySelector(`.step-status[data-step="${step}"]`);
  const row = document.querySelector(`.step-row[data-step="${step}"]`);

  if (statusEl) statusEl.textContent = STATUS_ICONS[status] || '';
  if (row) {
    row.className = `step-row ${status}`;
  }

  updateButtonStates();
  updateProgressCounter();
}

function updateProgressCounter() {
  let completed = 0;
  document.querySelectorAll('.step-row').forEach(row => {
    if (row.classList.contains('completed')) completed++;
  });
  stepsProgress.textContent = `${completed} / 9`;
}

function updateButtonStates() {
  const statuses = {};
  document.querySelectorAll('.step-row').forEach(row => {
    const step = Number(row.dataset.step);
    if (row.classList.contains('completed')) statuses[step] = 'completed';
    else if (row.classList.contains('running')) statuses[step] = 'running';
    else if (row.classList.contains('failed')) statuses[step] = 'failed';
    else if (row.classList.contains('stopped')) statuses[step] = 'stopped';
    else statuses[step] = 'pending';
  });

  const anyRunning = Object.values(statuses).some(s => s === 'running');

  for (let step = 1; step <= 9; step++) {
    const btn = document.querySelector(`.step-btn[data-step="${step}"]`);
    if (!btn) continue;

    if (anyRunning) {
      btn.disabled = true;
    } else if (step === 1) {
      btn.disabled = false;
    } else {
      const prevStatus = statuses[step - 1];
      const currentStatus = statuses[step];
      btn.disabled = !(prevStatus === 'completed' || currentStatus === 'failed' || currentStatus === 'completed' || currentStatus === 'stopped');
    }
  }

  updateStopButtonState(anyRunning || autoContinueBar.style.display !== 'none');
}

function updateStopButtonState(active) {
  btnStop.disabled = !active;
}

function updateStatusDisplay(state) {
  if (!state || !state.stepStatuses) return;

  statusBar.className = 'status-bar';

  const running = Object.entries(state.stepStatuses).find(([, s]) => s === 'running');
  if (running) {
    displayStatus.textContent = `Step ${running[0]} running...`;
    statusBar.classList.add('running');
    return;
  }

  const failed = Object.entries(state.stepStatuses).find(([, s]) => s === 'failed');
  if (failed) {
    displayStatus.textContent = `Step ${failed[0]} failed`;
    statusBar.classList.add('failed');
    return;
  }

  const stopped = Object.entries(state.stepStatuses).find(([, s]) => s === 'stopped');
  if (stopped) {
    displayStatus.textContent = `Step ${stopped[0]} stopped`;
    statusBar.classList.add('stopped');
    return;
  }

  const lastCompleted = Object.entries(state.stepStatuses)
    .filter(([, s]) => s === 'completed')
    .map(([k]) => Number(k))
    .sort((a, b) => b - a)[0];

  if (lastCompleted === 9) {
    displayStatus.textContent = 'All steps completed!';
    statusBar.classList.add('completed');
  } else if (lastCompleted) {
    displayStatus.textContent = `Step ${lastCompleted} done`;
  } else {
    displayStatus.textContent = 'Ready';
  }
}

function appendLog(entry) {
  const time = new Date(entry.timestamp).toLocaleTimeString('en-US', { hour12: false });
  const levelLabel = entry.level.toUpperCase();
  const line = document.createElement('div');
  line.className = `log-line log-${entry.level}`;

  const stepMatch = entry.message.match(/Step (\d)/);
  const stepNum = stepMatch ? stepMatch[1] : null;

  let html = `<span class="log-time">${time}</span> `;
  html += `<span class="log-level log-level-${entry.level}">${levelLabel}</span> `;
  if (stepNum) {
    html += `<span class="log-step-tag step-${stepNum}">S${stepNum}</span>`;
  }
  html += `<span class="log-msg">${escapeHtml(entry.message)}</span>`;

  line.innerHTML = html;
  logArea.appendChild(line);
  logArea.scrollTop = logArea.scrollHeight;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

async function fetchBurnerEmail() {
  const defaultLabel = 'Auto';
  btnFetchEmail.disabled = true;
  btnFetchEmail.textContent = '...';

  try {
    let response = await chrome.runtime.sendMessage({
      type: 'FETCH_BURNER_EMAIL',
      source: 'sidepanel',
      payload: { generateNew: true },
    });

    if (response?.error && /security verification required/i.test(response.error)) {
      const confirmed = window.confirm(
        'Burner Mailbox 需要先完成人机验证。\n\n请切到邮箱页完成验证，完成后点“确定”，我会直接继续获取邮箱，不需要你再点 Auto。'
      );
      if (!confirmed) {
        throw new Error(response.error);
      }

      response = await chrome.runtime.sendMessage({
        type: 'CONTINUE_BURNER_AFTER_CHALLENGE',
        source: 'sidepanel',
        payload: { generateNew: true },
      });
    }

    if (response?.error) {
      throw new Error(response.error);
    }
    if (!response?.email) {
      throw new Error('Burner Mailbox email was not returned.');
    }

    inputEmail.value = response.email;
    showToast(`已获取邮箱 ${response.email}`, 'success', 2500);
    return response.email;
  } catch (err) {
    showToast(`自动获取邮箱失败：${err.message}`, 'error');
    throw err;
  } finally {
    btnFetchEmail.disabled = false;
    btnFetchEmail.textContent = defaultLabel;
  }
}

function syncPasswordToggleLabel() {
  btnTogglePassword.textContent = inputPassword.type === 'password' ? 'Show' : 'Hide';
}

// ============================================================
// Button Handlers
// ============================================================

document.querySelectorAll('.step-btn').forEach(btn => {
  btn.addEventListener('click', async () => {
    const step = Number(btn.dataset.step);
    if (step === 3) {
      const email = inputEmail.value.trim();
      if (!email) {
        showToast('Please paste an email address or use Auto first', 'warn');
        return;
      }
      await chrome.runtime.sendMessage({ type: 'EXECUTE_STEP', source: 'sidepanel', payload: { step, email } });
    } else {
      await chrome.runtime.sendMessage({ type: 'EXECUTE_STEP', source: 'sidepanel', payload: { step } });
    }
  });
});

btnFetchEmail.addEventListener('click', async () => {
  await fetchBurnerEmail().catch(() => {});
});

btnTogglePassword.addEventListener('click', () => {
  inputPassword.type = inputPassword.type === 'password' ? 'text' : 'password';
  syncPasswordToggleLabel();
});

btnStop.addEventListener('click', async () => {
  btnStop.disabled = true;
  await chrome.runtime.sendMessage({ type: 'STOP_FLOW', source: 'sidepanel', payload: {} });
  showToast('Stopping current flow...', 'warn', 2000);
});

// Auto Run
btnAutoRun.addEventListener('click', async () => {
  const totalRuns = parseInt(inputRunCount.value) || 1;
  btnAutoRun.disabled = true;
  inputRunCount.disabled = true;
  btnAutoRun.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> Running...';
  await chrome.runtime.sendMessage({ type: 'AUTO_RUN', source: 'sidepanel', payload: { totalRuns } });
});

btnAutoContinue.addEventListener('click', async () => {
  if (autoContinueMode === 'email') {
    const email = inputEmail.value.trim();
    if (!email) {
      showToast('Please fetch or paste a Burner Mailbox email first!', 'warn');
      return;
    }
    autoContinueBar.style.display = 'none';
    autoContinueMode = 'email';
    await chrome.runtime.sendMessage({ type: 'RESUME_AUTO_RUN', source: 'sidepanel', payload: { email } });
    return;
  }

  autoContinueBar.style.display = 'none';
  autoContinueMode = 'email';
  await chrome.runtime.sendMessage({ type: 'RESUME_AUTO_RUN', source: 'sidepanel', payload: {} });
});

// Reset
btnReset.addEventListener('click', async () => {
  if (confirm('Reset all steps and data?')) {
    await chrome.runtime.sendMessage({ type: 'RESET', source: 'sidepanel' });
    displayOauthUrl.textContent = 'Waiting...';
    displayOauthUrl.classList.remove('has-value');
    displayLocalhostUrl.textContent = 'Waiting...';
    displayLocalhostUrl.classList.remove('has-value');
    if (selectEmailMode.value !== 'imap') {
      inputEmail.value = '';
    }
    displayStatus.textContent = 'Ready';
    statusBar.className = 'status-bar';
    logArea.innerHTML = '';
    document.querySelectorAll('.step-row').forEach(row => row.className = 'step-row');
    document.querySelectorAll('.step-status').forEach(el => el.textContent = '');
    btnAutoRun.disabled = false;
    inputRunCount.disabled = false;
    btnAutoRun.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg> Auto';
    autoContinueBar.style.display = 'none';
    updateStopButtonState(false);
    updateButtonStates();
    updateProgressCounter();
  }
});

// Clear log
btnClearLog.addEventListener('click', () => {
  logArea.innerHTML = '';
});

// Save settings on change
inputEmail.addEventListener('change', async () => {
  const email = inputEmail.value.trim();
  if (email) {
    await chrome.runtime.sendMessage({ type: 'SAVE_EMAIL', source: 'sidepanel', payload: { email } });
  }
});

inputVpsUrl.addEventListener('change', async () => {
  const vpsUrl = inputVpsUrl.value.trim();
  await chrome.runtime.sendMessage({ type: 'SAVE_SETTING', source: 'sidepanel', payload: { vpsUrl } });
});

inputPassword.addEventListener('change', async () => {
  await chrome.runtime.sendMessage({
    type: 'SAVE_SETTING',
    source: 'sidepanel',
    payload: { customPassword: inputPassword.value },
  });
});

// IMAP mode settings
selectEmailMode.addEventListener('change', async () => {
  const mode = selectEmailMode.value;
  applyEmailModeUI(mode);
  await chrome.runtime.sendMessage({
    type: 'SAVE_IMAP_SETTINGS',
    source: 'sidepanel',
    payload: { emailMode: mode },
  });
});

inputImapEmailList.addEventListener('change', async () => {
  const list = inputImapEmailList.value.split('\n').map(e => e.trim()).filter(Boolean);
  await chrome.runtime.sendMessage({
    type: 'SAVE_IMAP_SETTINGS',
    source: 'sidepanel',
    payload: { imapEmailList: list },
  });
});

inputImapBridgeHost.addEventListener('change', async () => {
  await chrome.runtime.sendMessage({
    type: 'SAVE_IMAP_SETTINGS',
    source: 'sidepanel',
    payload: { imapBridgeHost: inputImapBridgeHost.value.trim() || '127.0.0.1' },
  });
});

inputImapBridgePort.addEventListener('change', async () => {
  const port = parseInt(inputImapBridgePort.value) || 9090;
  await chrome.runtime.sendMessage({
    type: 'SAVE_IMAP_SETTINGS',
    source: 'sidepanel',
    payload: { imapBridgePort: port },
  });
});

// Proxy settings
selectProxyType.addEventListener('change', async () => {
  const type = selectProxyType.value;
  applyProxyUI(type);
  await chrome.runtime.sendMessage({
    type: 'SAVE_PROXY_SETTINGS',
    source: 'sidepanel',
    payload: { proxyType: type },
  });
});

inputProxyHost.addEventListener('change', async () => {
  await chrome.runtime.sendMessage({
    type: 'SAVE_PROXY_SETTINGS',
    source: 'sidepanel',
    payload: { proxyHost: inputProxyHost.value.trim() },
  });
});

inputProxyPort.addEventListener('change', async () => {
  const port = parseInt(inputProxyPort.value) || 1080;
  await chrome.runtime.sendMessage({
    type: 'SAVE_PROXY_SETTINGS',
    source: 'sidepanel',
    payload: { proxyPort: port },
  });
});

inputProxyUser.addEventListener('change', async () => {
  await chrome.runtime.sendMessage({
    type: 'SAVE_PROXY_SETTINGS',
    source: 'sidepanel',
    payload: { proxyUser: inputProxyUser.value },
  });
});

inputProxyPass.addEventListener('change', async () => {
  await chrome.runtime.sendMessage({
    type: 'SAVE_PROXY_SETTINGS',
    source: 'sidepanel',
    payload: { proxyPass: inputProxyPass.value },
  });
});

// ============================================================
// Listen for Background broadcasts
// ============================================================

chrome.runtime.onMessage.addListener((message) => {
  switch (message.type) {
    case 'LOG_ENTRY':
      appendLog(message.payload);
      if (message.payload.level === 'error') {
        showToast(message.payload.message, 'error');
      }
      break;

    case 'STEP_STATUS_CHANGED': {
      const { step, status } = message.payload;
      updateStepUI(step, status);
      chrome.runtime.sendMessage({ type: 'GET_STATE', source: 'sidepanel' }).then(updateStatusDisplay);
      if (status === 'completed') {
        chrome.runtime.sendMessage({ type: 'GET_STATE', source: 'sidepanel' }).then(state => {
          syncPasswordField(state);
          if (state.oauthUrl) {
            displayOauthUrl.textContent = state.oauthUrl;
            displayOauthUrl.classList.add('has-value');
          }
          if (state.localhostUrl) {
            displayLocalhostUrl.textContent = state.localhostUrl;
            displayLocalhostUrl.classList.add('has-value');
          }
        });
      }
      break;
    }

    case 'AUTO_RUN_RESET': {
      // Full UI reset for next run
      displayOauthUrl.textContent = 'Waiting...';
      displayOauthUrl.classList.remove('has-value');
      displayLocalhostUrl.textContent = 'Waiting...';
      displayLocalhostUrl.classList.remove('has-value');
      // In IMAP mode, the email gets set automatically — keep field readable but clear it
      if (selectEmailMode.value !== 'imap') {
        inputEmail.value = '';
      }
      displayStatus.textContent = 'Ready';
      statusBar.className = 'status-bar';
      logArea.innerHTML = '';
      document.querySelectorAll('.step-row').forEach(row => row.className = 'step-row');
      document.querySelectorAll('.step-status').forEach(el => el.textContent = '');
      updateStopButtonState(false);
      autoContinueMode = 'email';
      autoContinueHint.textContent = 'Use Auto to fetch a Burner Mailbox email, or paste manually, then continue';
      updateProgressCounter();
      break;
    }

    case 'DATA_UPDATED': {
      if (message.payload.email) {
        inputEmail.value = message.payload.email;
      }
      if (message.payload.password !== undefined) {
        inputPassword.value = message.payload.password || '';
      }
      if (message.payload.oauthUrl) {
        displayOauthUrl.textContent = message.payload.oauthUrl;
        displayOauthUrl.classList.add('has-value');
      }
      if (message.payload.localhostUrl) {
        displayLocalhostUrl.textContent = message.payload.localhostUrl;
        displayLocalhostUrl.classList.add('has-value');
      }
      break;
    }

    case 'AUTO_RUN_STATUS': {
      const { phase, currentRun, totalRuns } = message.payload;
      const runLabel = totalRuns > 1 ? ` (${currentRun}/${totalRuns})` : '';
      switch (phase) {
        case 'waiting_email':
          autoContinueBar.style.display = 'flex';
          autoContinueMode = 'email';
          autoContinueHint.textContent = 'Use Auto to fetch a Burner Mailbox email, or paste manually, then continue';
          btnAutoRun.innerHTML = `Paused${runLabel}`;
          updateStopButtonState(true);
          break;
        case 'waiting_challenge':
          autoContinueBar.style.display = 'flex';
          autoContinueMode = 'challenge';
          autoContinueHint.textContent = 'Burner Mailbox 需要先完成人机验证。请在邮箱页完成验证后点击“继续”';
          btnAutoRun.innerHTML = `Paused${runLabel}`;
          updateStopButtonState(true);
          break;
        case 'running':
          btnAutoRun.innerHTML = `Running${runLabel}`;
          updateStopButtonState(true);
          break;
        case 'complete':
          btnAutoRun.disabled = false;
          inputRunCount.disabled = false;
          btnAutoRun.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg> Auto';
          autoContinueBar.style.display = 'none';
          autoContinueMode = 'email';
          autoContinueHint.textContent = 'Use Auto to fetch a Burner Mailbox email, or paste manually, then continue';
          updateStopButtonState(false);
          break;
        case 'stopped':
          btnAutoRun.disabled = false;
          inputRunCount.disabled = false;
          btnAutoRun.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg> Auto';
          autoContinueBar.style.display = 'none';
          autoContinueMode = 'email';
          autoContinueHint.textContent = 'Use Auto to fetch a Burner Mailbox email, or paste manually, then continue';
          updateStopButtonState(false);
          break;
      }
      break;
    }
  }
});

// ============================================================
// Theme Toggle
// ============================================================

const btnTheme = document.getElementById('btn-theme');

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('multipage-theme', theme);
}

function initTheme() {
  const saved = localStorage.getItem('multipage-theme');
  if (saved) {
    setTheme(saved);
  } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
    setTheme('dark');
  }
}

btnTheme.addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme');
  setTheme(current === 'dark' ? 'light' : 'dark');
});

// ============================================================
// Init
// ============================================================

initTheme();
restoreState().then(() => {
  syncPasswordToggleLabel();
  updateButtonStates();
});
