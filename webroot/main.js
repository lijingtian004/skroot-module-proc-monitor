// main.js — 进程监控 WebUI 前端逻辑

// ============ 全局状态 ============
let allEvents = [];
let allAlerts = [];
let stats = { total: 0, alerts: 0, exec: 0, exit: 0 };
let currentTab = 'live';
let pollTimer = null;
let lastEventCount = 0;

// ============ API 调用 ============
async function api(path, body = '') {
  try {
    const resp = await fetch(new URL(path, window.location.href), {
      method: 'POST',
      body: body,
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return await resp.text();
  } catch (e) {
    console.error(`API error [${path}]:`, e);
    return null;
  }
}

// ============ 数据拉取 ============
async function fetchEvents() {
  const raw = await api('/api/events', '200');
  if (raw) {
    try {
      allEvents = JSON.parse(raw);
    } catch (e) {}
  }
}

async function fetchAlerts() {
  const raw = await api('/api/alerts', '100');
  if (raw) {
    try {
      allAlerts = JSON.parse(raw);
    } catch (e) {}
  }
}

async function fetchStats() {
  const raw = await api('/api/stats');
  if (raw) {
    try {
      const s = JSON.parse(raw);
      stats.total  = s.total_events  || 0;
      stats.alerts = s.total_alerts  || 0;
      updateStatsUI();
    } catch (e) {}
  }
}

async function manualScan() {
  await api('/api/scan');
  // 短暂延迟后刷新
  setTimeout(pollAll, 300);
}

// ============ UI 更新 ============

function updateStatsUI() {
  document.getElementById('statTotal').textContent  = formatNum(stats.total);
  document.getElementById('statAlerts').textContent  = formatNum(stats.alerts);
  document.getElementById('statExec').textContent    = formatNum(stats.total - stats.exit - stats.alerts);
  document.getElementById('statExit').textContent    = formatNum(stats.exit || 0);

  // 告警角标
  const badge = document.getElementById('alertBadge');
  if (stats.alerts > 0) {
    badge.style.display = 'inline';
    badge.textContent = stats.alerts;
  } else {
    badge.style.display = 'none';
  }
}

function formatNum(n) {
  if (n >= 10000) return (n / 1000).toFixed(1) + 'k';
  return String(n);
}

function formatTime(ts) {
  const d = new Date(ts);
  const pad = n => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function formatTimestamp(ts) {
  const d = new Date(ts);
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds())}`;
}

function typeIcon(type) {
  switch (type) {
    case 0: return '🟢';  // EXEC
    case 1: return '⚪';  // EXIT
    case 2: return '🔴';  // ALERT
    default: return '❓';
  }
}

function typeLabel(type) {
  switch (type) {
    case 0: return '启动';
    case 1: return '退出';
    case 2: return '告警';
    default: return '未知';
  }
}

function typeClass(type) {
  switch (type) {
    case 0: return 'exec-item';
    case 1: return 'exit-item';
    case 2: return 'alert-item';
    default: return '';
  }
}

function uidToName(uid) {
  if (uid === 0) return 'root';
  if (uid >= 10000 && uid < 20000) return `u${Math.floor(uid/10000)-1} (App)`;
  if (uid === 2000) return 'shell';
  return `uid:${uid}`;
}

// ============ 渲染 ============

function renderEventItem(ev, isNew) {
  const div = document.createElement('div');
  div.className = `event-item ${typeClass(ev.type)}${isNew ? ' new' : ''}`;
  div.onclick = () => showDetail(ev);

  const icon = typeIcon(ev.type);
  const time = formatTime(ev.ts);
  const reason = ev.reason ? `<div class="event-reason">⚠️ ${escHtml(ev.reason)}</div>` : '';
  const cmdline = ev.cmdline ? escHtml(ev.cmdline.substring(0, 80)) : '';

  div.innerHTML = `
    <span class="event-icon">${icon}</span>
    <div class="event-body">
      <div class="event-main">
        <span class="comm">${escHtml(ev.comm)}</span>
        <span class="pid">PID ${ev.pid}</span>
      </div>
      <div class="event-sub">${cmdline || `PPID ${ev.ppid} · ${uidToName(ev.uid)}`}</div>
      ${reason}
    </div>
    <span class="event-time">${time}</span>
  `;
  return div;
}

function renderLiveList() {
  const list = document.getElementById('liveList');
  const autoScroll = document.getElementById('autoScroll').checked;
  const wasAtTop = list.scrollTop < 50;

  list.innerHTML = '';
  // 统计各类型数量
  stats.exit = allEvents.filter(e => e.type === 1).length;

  for (const ev of allEvents) {
    list.appendChild(renderEventItem(ev, false));
  }

  if (autoScroll && wasAtTop) {
    list.scrollTop = 0;
  }
}

function renderAlertList() {
  const list = document.getElementById('alertList');
  const summary = document.getElementById('alertSummary');

  if (allAlerts.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <span class="empty-icon">✅</span>
        <p>未检测到可疑进程</p>
      </div>`;
    summary.textContent = '暂无告警';
    return;
  }

  summary.textContent = `共 ${allAlerts.length} 条告警`;
  list.innerHTML = '';

  for (const ev of allAlerts) {
    list.appendChild(renderEventItem(ev, false));
  }
}

function renderHistoryList(events) {
  const list = document.getElementById('historyList');
  list.innerHTML = '';

  if (events.length === 0) {
    list.innerHTML = '<div class="loading">无匹配记录</div>';
    return;
  }

  const display = events.slice(0, 200); // 最多显示 200 条
  for (const ev of display) {
    list.appendChild(renderEventItem(ev, false));
  }
}

// ============ 筛选 ============

function filterHistory() {
  const keyword = document.getElementById('searchInput').value.toLowerCase();
  const typeFilter = document.getElementById('filterType').value;

  let filtered = allEvents;

  if (typeFilter !== 'all') {
    const typeMap = { exec: 0, exit: 1, alert: 2 };
    filtered = filtered.filter(e => e.type === typeMap[typeFilter]);
  }

  if (keyword) {
    filtered = filtered.filter(e =>
      e.comm.toLowerCase().includes(keyword) ||
      String(e.pid).includes(keyword) ||
      (e.cmdline && e.cmdline.toLowerCase().includes(keyword))
    );
  }

  renderHistoryList(filtered);
}

// ============ 事件详情浮层 ============

function showDetail(ev) {
  const overlay = document.getElementById('modalOverlay');
  const body = document.getElementById('modalBody');
  const title = document.getElementById('modalTitle');

  title.textContent = `${typeIcon(ev.type)} ${ev.comm} — ${typeLabel(ev.type)}`;

  const rows = [
    ['类型', typeLabel(ev.type)],
    ['时间', formatTimestamp(ev.ts)],
    ['PID', ev.pid],
    ['PPID', ev.ppid],
    ['UID', `${ev.uid} (${uidToName(ev.uid)})`],
    ['进程名', ev.comm],
  ];

  if (ev.cmdline) rows.push(['命令行', ev.cmdline]);
  if (ev.reason) rows.push(['告警原因', ev.reason]);

  body.innerHTML = rows.map(([label, value]) =>
    `<div class="detail-row">
      <span class="detail-label">${escHtml(label)}</span>
      <span class="detail-value">${escHtml(String(value))}</span>
    </div>`
  ).join('');

  overlay.classList.add('show');
}

function closeModal() {
  document.getElementById('modalOverlay').classList.remove('show');
}

// ============ Tab 切换 ============

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab').forEach(t => {
    t.classList.toggle('active', t.dataset.tab === tab);
  });
  document.querySelectorAll('.panel').forEach(p => {
    p.classList.toggle('active', p.id === `panel-${tab}`);
  });

  // 切换时刷新数据
  if (tab === 'alerts') renderAlertList();
  if (tab === 'history') filterHistory();
}

// ============ 轮询 ============

async function pollAll() {
  await Promise.all([fetchEvents(), fetchAlerts(), fetchStats()]);

  // 更新状态指示
  const dot = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  dot.classList.add('online');
  text.textContent = '在线';

  // 根据当前 tab 刷新对应面板
  if (currentTab === 'live')    renderLiveList();
  if (currentTab === 'alerts')  renderAlertList();
  if (currentTab === 'history') filterHistory();
}

function startPolling() {
  pollAll();
  pollTimer = setInterval(pollAll, 1500); // 1.5 秒轮询
}

// ============ 工具函数 ============

function escHtml(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

// ============ 启动 ============

document.addEventListener('DOMContentLoaded', startPolling);
