import { PREFIX } from './api.js';

export const CANARY_KEY = `${PREFIX}canary`;
const LOG_KEY = `${PREFIX}log`;
const BLOCK_KEY = `${PREFIX}blockedUntil`;
const REFRESH_KEY = `${PREFIX}refreshes`;

let blockTimer = null;

function getLog() {
  try {
    const raw = localStorage.getItem(LOG_KEY);
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveLog(log) {
  try {
    localStorage.setItem(LOG_KEY, JSON.stringify(log.slice(-30)));
  } catch { /* ignore */ }
}

function startBlock(durationMs = 30000) {
  const until = Date.now() + durationMs;
  try { localStorage.setItem(BLOCK_KEY, String(until)); } catch {}
  updateBlockUI();
}

function updateBlockUI() {
  const statusEl = document.querySelector('#security-status');
  const detailEl = document.querySelector('#restriction-detail');
  
  if (!statusEl) return;
  
  let until = 0;
  try { until = Number(localStorage.getItem(BLOCK_KEY)) || 0; } catch {}
  
  const remaining = until - Date.now();
  
  if (remaining > 0) {
    statusEl.textContent = 'Действия ограничены';
    detailEl.hidden = false;
    detailEl.textContent = `Попробуйте снова через ${Math.ceil(remaining / 1000)} сек.`;
    
    document.querySelector('#submit-button').disabled = true;
    document.querySelector('#refresh-button').disabled = true;
    
    clearTimeout(blockTimer);
    blockTimer = setTimeout(updateBlockUI, 1000);
  } else {
    statusEl.textContent = 'Ограничений нет';
    detailEl.hidden = true;
    document.querySelector('#submit-button').disabled = false;
    document.querySelector('#refresh-button').disabled = false;
    try { localStorage.removeItem(BLOCK_KEY); } catch {}
  }
}

export function reportIncident(type, reason) {
  const log = getLog();
  log.push({ time: Date.now(), type, reason });
  saveLog(log);

  const list = document.querySelector('#incident-list');
  const item = document.createElement('li');
  item.textContent = `${new Date().toLocaleTimeString()} — ${type}: ${reason}`;
  list.prepend(item);
  
  document.querySelector('#incidents-empty').hidden = true;
  document.querySelector('#incident-count').textContent = String(list.children.length);

  startBlock(30000);
}

export function checkActivity(action, details = {}) {
  if (action === 'startup') {
    try {
      const canary = JSON.parse(localStorage.getItem(CANARY_KEY));
      if (canary && canary.role === 'admin') {
        reportIncident('T5', 'Изменен маркер роли на admin');
        localStorage.setItem(CANARY_KEY, JSON.stringify({ role: 'visitor' }));
      }
    } catch {}

    const url = new URL(window.location.href);
    if (url.searchParams.get('staff') === '1') {
      reportIncident('T6', 'Попытка доступа по параметру staff=1');
      url.searchParams.delete('staff');
      window.history.replaceState({}, '', url);
    }
  }

  if (action === 'refresh') {
    const now = Date.now();
    let refreshes = [];
    try {
      refreshes = JSON.parse(localStorage.getItem(REFRESH_KEY)) || [];
    } catch {}
    refreshes = refreshes.filter(t => now - t < 5000);
    refreshes.push(now);
    localStorage.setItem(REFRESH_KEY, JSON.stringify(refreshes));
    
    if (refreshes.length >= 6) {
      reportIncident('T1', 'Слишком частая перезагрузка списка');
      localStorage.removeItem(REFRESH_KEY);
    }
  }

  if (action === 'submit') {
    if (details.supportCode && details.supportCode.length > 0) {
      reportIncident('T2', 'Заполнено скрытое поле supportCode');
    }

    const validTopics = ['html', 'javascript', 'api'];
    if (details.topic && !validTopics.includes(details.topic)) {
      reportIncident('T4', `Недопустимое направление: ${details.topic}`);
    }
  }

  if (action === 'decoy') {
    reportIncident('T3', 'Нажата скрытая служебная кнопка staff-export');
  }
}

export function isRestricted() {
  try {
    const until = Number(localStorage.getItem(BLOCK_KEY)) || 0;
    return Date.now() < until;
  } catch {
    return false;
  }
}

export function initializeSecurity() {
  try {
    if (localStorage.getItem(CANARY_KEY) === null) {
      localStorage.setItem(CANARY_KEY, JSON.stringify({ role: 'visitor' }));
    }
  } catch {}
  
  const log = getLog();
  const list = document.querySelector('#incident-list');
  list.replaceChildren();
  log.forEach(event => {
    const item = document.createElement('li');
    item.textContent = `${new Date(event.time).toLocaleTimeString()} — ${event.type}: ${event.reason}`;
    list.append(item);
  });
  
  if (log.length > 0) {
    document.querySelector('#incidents-empty').hidden = true;
    document.querySelector('#incident-count').textContent = String(log.length);
  }

  updateBlockUI();
  checkActivity('startup');
}

export function resetSecurity() {
  clearTimeout(blockTimer);
  try {
    for (const key of Object.keys(localStorage)) {
      if (key.startsWith(PREFIX) && key !== `${PREFIX}applications`) localStorage.removeItem(key);
    }
    localStorage.setItem(CANARY_KEY, JSON.stringify({ role: 'visitor' }));
  } catch {}
  
  document.querySelector('#incident-list').replaceChildren();
  document.querySelector('#incident-count').textContent = '0';
  document.querySelector('#incidents-empty').hidden = false;
  document.querySelector('#security-status').textContent = 'Ограничений нет';
  document.querySelector('#restriction-detail').hidden = true;
  document.querySelector('#submit-button').disabled = false;
  document.querySelector('#refresh-button').disabled = false;
}