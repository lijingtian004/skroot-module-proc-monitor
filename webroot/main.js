// main.js — 进程监控 WebUI 前端逻辑

// ============ 全局状态 ============
let allEvents = [];
let allAlerts = [];
let allProcs = [];  // 当前进程列表
let filteredProcs = [];  // 筛选后的进程
let currentProcCat = 'all';  // 当前分类筛选
let stats = { total: 0, alerts: 0, exec: 0, exit: 0 };
let currentTab = 'procs';
let pollTimer = null;
let chargingInfo = null;

// ============ 进程分类 ============
const PROC_CATS = {
  system:  { icon: '🔵', label: '系统核心', color: '#3b82f6' },
  service: { icon: '🟢', label: '系统服务', color: '#22c55e' },
  app:     { icon: '🟡', label: '用户应用', color: '#f59e0b' },
  shell:   { icon: '🟠', label: 'Shell', color: '#f97316' },
  risky:   { icon: '🔴', label: '可疑', color: '#ef4444' },
};

const SYSTEM_NAMES = [
  'system_server', 'init', 'zygote', 'zygote64', 'servicemanager',
  'binder', 'hwservicemanager', 'vndservicemanager', 'ueventd',
  'logd', 'lmkd', 'installd', 'tombstoned', 'crash_dump',
  'linker', 'linker64', 'app_process', 'heapprofd',
];

const RISKY_NAMES = [
  'magisk', 'magiskd', 'su', 'frida', 'lsposed', 'lsposedd',
  'riru', 'zygisk', 'shamiko', 'xposed', 'edxposed',
  'kernelsu', 'apatch', 'strace', 'ltrace', 'gdb', 'gdbserver',
];

const SHELL_NAMES = ['sh', 'bash', 'logcat', 'adb', 'adbd', 'toybox', 'toybox64'];

function classifyProc(p) {
  const comm = (p.comm || '').toLowerCase();
  const cmdline = (p.cmdline || '').toLowerCase();
  const uid = p.uid;

  // 1. 可疑进程（最高优先级）
  for (const name of RISKY_NAMES) {
    if (comm.includes(name) || cmdline.includes(name)) return 'risky';
  }

  // 2. 系统核心
  if (uid === 0 || uid === 1000) {
    for (const name of SYSTEM_NAMES) {
      if (comm.includes(name)) return 'system';
    }
    // root 或 system 用户的其他进程也归为系统
    return 'system';
  }

  // 3. Shell/调试
  if (uid === 2000) {
    for (const name of SHELL_NAMES) {
      if (comm.includes(name)) return 'shell';
    }
    return 'shell';
  }

  // 4. 用户应用 (uid >= 10000)
  if (uid >= 10000) return 'app';

  // 5. 其他系统服务 (uid < 10000, 非 root/system)
  return 'service';
}

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

async function fetchProcs() {
  const raw = await api('/api/procs');
  if (raw) {
    try {
      allProcs = JSON.parse(raw).map(p => ({ ...p, cat: classifyProc(p) }));
      updateProcCounts();
      if (currentTab === 'procs') filterProcs();
    } catch (e) {}
  }
}

async function fetchCharging() {
  const raw = await api('/api/charging');
  if (raw) {
    try {
      chargingInfo = JSON.parse(raw);
      if (currentTab === 'charging') renderChargingInfo();
    } catch (e) {}
  }
}

function updateProcCounts() {
  // 统计各分类数量
  const counts = { all: allProcs.length, system: 0, service: 0, app: 0, shell: 0, risky: 0 };
  for (const p of allProcs) {
    counts[p.cat]++;
  }

  // 更新角标
  const badge = document.getElementById('procBadge');
  if (badge) badge.textContent = counts.all;

  // 更新分类按钮
  document.querySelectorAll('.cat-btn').forEach(btn => {
    const cat = btn.dataset.cat;
    const count = counts[cat] || 0;
    const label = btn.querySelector('.cat-label');
    const countSpan = btn.querySelector('.cat-count');
    if (countSpan) countSpan.textContent = count;
  });

  // 更新计数显示
  const count = document.getElementById('procCount');
  if (count) {
    const parts = [];
    for (const [key, val] of Object.entries(PROC_CATS)) {
      parts.push(`${val.icon} ${counts[key]}`);
    }
    count.textContent = `共 ${counts.all} 个进程 · ${parts.join(' · ')}`;
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
    case 0: return '▶';
    case 1: return '■';
    case 2: return '⚠';
    default: return '?';
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
  const iconClass = ev.type === 0 ? 'exec' : ev.type === 1 ? 'exit' : 'alert';
  const time = formatTime(ev.ts);
  const reason = ev.reason ? `<div class="event-reason">⚠ ${escHtml(ev.reason)}</div>` : '';
  const cmdline = ev.cmdline ? escHtml(ev.cmdline.substring(0, 80)) : '';

  div.innerHTML = `
    <span class="event-icon ${iconClass}">${icon}</span>
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

// ============ 进程列表 ============

function renderProcItem(p) {
  const div = document.createElement('div');
  const cat = PROC_CATS[p.cat] || PROC_CATS.service;
  div.className = 'event-item proc-item';
  div.style.borderLeftColor = cat.color;
  div.onclick = () => showProcDetail(p);

  const cmdline = p.cmdline ? escHtml(p.cmdline.substring(0, 60)) : '';

  div.innerHTML = `
    <span class="event-icon">${cat.icon}</span>
    <div class="event-body">
      <div class="event-main">
        <span class="comm">${escHtml(p.comm)}</span>
        <span class="pid">PID ${p.pid}</span>
      </div>
      <div class="event-sub">${cmdline || `PPID ${p.ppid} · ${uidToName(p.uid)}`}</div>
    </div>
  `;
  return div;
}

function renderProcsList(procs) {
  const list = document.getElementById('procList');
  list.innerHTML = '';

  if (procs.length === 0) {
    list.innerHTML = '<div class="loading">无进程数据</div>';
    return;
  }

  const display = procs.slice(0, 500); // 最多显示 500 条
  for (const p of display) {
    list.appendChild(renderProcItem(p));
  }
}

function filterProcs() {
  const keyword = document.getElementById('procSearchInput').value.toLowerCase();

  filteredProcs = allProcs;

  // 分类筛选
  if (currentProcCat !== 'all') {
    filteredProcs = filteredProcs.filter(p => p.cat === currentProcCat);
  }

  // 关键词搜索
  if (keyword) {
    filteredProcs = filteredProcs.filter(p =>
      p.comm.toLowerCase().includes(keyword) ||
      String(p.pid).includes(keyword) ||
      (p.cmdline && p.cmdline.toLowerCase().includes(keyword))
    );
  }

  // 更新计数
  const count = document.getElementById('procCount');
  if (count && keyword) {
    count.textContent = `匹配 ${filteredProcs.length} / ${allProcs.length} 个进程`;
  } else if (count) {
    updateProcCounts();
  }

  renderProcsList(filteredProcs);
}

function switchProcCat(cat) {
  currentProcCat = cat;
  document.querySelectorAll('.cat-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.cat === cat);
  });
  filterProcs();
}

function showProcDetail(p) {
  const overlay = document.getElementById('modalOverlay');
  const body = document.getElementById('modalBody');
  const title = document.getElementById('modalTitle');
  const cat = PROC_CATS[p.cat] || PROC_CATS.service;

  title.textContent = `${cat.icon} ${p.comm} — 进程详情`;

  const rows = [
    ['分类', `${cat.icon} ${cat.label}`],
    ['PID', p.pid],
    ['PPID', p.ppid],
    ['UID', `${p.uid} (${uidToName(p.uid)})`],
    ['进程名', p.comm],
  ];

  if (p.cmdline) rows.push(['命令行', p.cmdline]);

  body.innerHTML = rows.map(([label, value]) =>
    `<div class="detail-row">
      <span class="detail-label">${escHtml(label)}</span>
      <span class="detail-value">${escHtml(String(value))}</span>
    </div>`
  ).join('');

  overlay.classList.add('show');
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
  if (tab === 'procs')   { fetchProcs(); filterProcs(); }
  if (tab === 'alerts')  renderAlertList();
  if (tab === 'history') filterHistory();
  if (tab === 'charging') fetchCharging();
}

// ============ 轮询 ============

async function pollAll() {
  await Promise.all([fetchEvents(), fetchAlerts(), fetchStats(), fetchProcs(), fetchCharging()]);

  // 更新状态指示
  const dot = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  dot.classList.add('online');
  text.textContent = '在线';

  // 统计退出数
  stats.exit = allEvents.filter(e => e.type === 1).length;
  updateStatsUI();

  // 根据当前 tab 刷新对应面板
  if (currentTab === 'alerts')  renderAlertList();
  if (currentTab === 'history') filterHistory();
  if (currentTab === 'procs')   filterProcs();
  if (currentTab === 'charging') renderChargingInfo();
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

// ============ 充电信息渲染 ============

function speedLabel(speed) {
  const map = {
    'slow':    '🐢 慢充',
    'normal':  '🔋 标准充电',
    'fast':    '⚡ 快充',
    'super':   '🚀 极速快充',
    'unknown': '❓ 未知',
  };
  return map[speed] || speed;
}

function statusColor(status) {
  const s = (status || '').toLowerCase();
  if (s.includes('charging')) return '#22c55e';
  if (s.includes('discharging')) return '#f59e0b';
  if (s.includes('full')) return '#3b82f6';
  if (s.includes('not')) return '#94a3b8';
  return '#94a3b8';
}

function healthColor(pct) {
  if (pct >= 80) return '#22c55e';
  if (pct >= 50) return '#f59e0b';
  return '#ef4444';
}

function renderChargingInfo() {
  if (!chargingInfo) return;
  const ch = chargingInfo;

  // 顶部概览
  const overview = document.getElementById('chargingOverview');
  const sc = statusColor(ch.battery_status);
  const level = ch.battery_level >= 0 ? ch.battery_level : '?';

  // 进度条
  const barWidth = ch.battery_level >= 0 ? ch.battery_level : 0;
  const tempStr = ch.battery_temp > 0 ? (ch.battery_temp / 10).toFixed(1) + '°C' : '?';
  const voltageStr = ch.battery_voltage_mv > 0 ? ch.battery_voltage_mv + 'mV' : '?';
  const currentStr = ch.battery_current_ma !== 0 ? ch.battery_current_ma + 'mA' : '?';

  // 健康度
  let healthHtml = '';
  if (ch.battery_health_pct > 0) {
    const hpct = ch.battery_health_pct.toFixed(1);
    const hc = healthColor(hpct);
    healthHtml = `
      <div class="charge-health-bar">
        <div class="charge-health-label">电池健康度</div>
        <div class="charge-health-value" style="color:${hc}">${hpct}%</div>
        <div class="charge-health-track">
          <div class="charge-health-fill" style="width:${hpct}%;background:${hc}"></div>
        </div>
      </div>`;
  }

  overview.innerHTML = `
    <div class="charge-big-status" style="color:${sc}">
      ${ch.battery_status || '未知'}
    </div>
    <div class="charge-level">
      <div class="charge-level-num">${level}%</div>
      <div class="charge-level-bar">
        <div class="charge-level-fill" style="width:${barWidth}%;background:${sc}"></div>
      </div>
    </div>
    <div class="charge-speed-label">${speedLabel(ch.charger_speed)}</div>
    ${healthHtml}
  `;

  // 详细参数
  const details = document.getElementById('chargingDetails');
  const rows = [];
  if (voltageStr !== '?') rows.push(['电压', voltageStr]);
  if (currentStr !== '?') rows.push(['电流', currentStr]);
  if (tempStr !== '?') rows.push(['温度', tempStr]);
  if (ch.battery_health) rows.push(['健康', ch.battery_health]);
  if (ch.battery_technology) rows.push(['电池类型', ch.battery_technology]);
  if (ch.charge_type) rows.push(['充电类型', ch.charge_type]);
  if (ch.input_current_ma >= 0) rows.push(['输入电流上限', ch.input_current_ma + 'mA']);
  if (ch.pd_supported) rows.push(['PD协议', '支持']);
  if (ch.charge_full_uah > 0) rows.push(['满电容量', (ch.charge_full_uah / 1000).toFixed(0) + 'mAh']);
  if (ch.charge_full_design_uah > 0) rows.push(['设计容量', (ch.charge_full_design_uah / 1000).toFixed(0) + 'mAh']);

  if (rows.length > 0) {
    details.innerHTML = `
      <div class="section-title">📊 详细参数</div>
      <div class="detail-grid">
        ${rows.map(([label, value]) =>
          `<div class="detail-row">
            <span class="detail-label">${escHtml(label)}</span>
            <span class="detail-value">${escHtml(String(value))}</span>
          </div>`
        ).join('')}
      </div>`;
  } else {
    details.innerHTML = '';
  }

  // 电源设备列表
  const supplies = document.getElementById('chargingSupplies');
  let suppliesHtml = '<div class="section-title">🔌 检测到的电源设备</div>';
  if (ch.supplies && ch.supplies.length > 0) {
    for (const s of ch.supplies) {
      const statusC = statusColor(s.status);
      suppliesHtml += `
        <div class="supply-card">
          <div class="supply-header">
            <span class="supply-name">${escHtml(s.name)}</span>
            <span class="supply-type">${escHtml(s.type)}</span>
            <span class="supply-status" style="color:${statusC}">${escHtml(s.status || 'N/A')}</span>
          </div>
          <div class="supply-details">
            ${s.capacity >= 0 ? `<span>电量 ${s.capacity}%</span>` : ''}
            ${s.voltage_uv > 0 ? `<span>电压 ${(s.voltage_uv/1000000).toFixed(2)}V</span>` : ''}
            ${s.current_ua !== 0 ? `<span>电流 ${(s.current_ua/1000).toFixed(0)}mA</span>` : ''}
            ${s.temp > 0 ? `<span>温度 ${(s.temp/10).toFixed(1)}°C</span>` : ''}
            ${s.health[0] ? `<span>健康 ${escHtml(s.health)}</span>` : ''}
            ${s.charge_type[0] && s.charge_type !== 'N/A' ? `<span>充电 ${escHtml(s.charge_type)}</span>` : ''}
            ${s.technology[0] ? `<span>技术 ${escHtml(s.technology)}</span>` : ''}
            ${s.pd_allowed > 0 ? `<span>PD ✓</span>` : ''}
          </div>
        </div>`;
    }
  } else {
    suppliesHtml += '<div class="empty-state"><p>未检测到电源设备</p></div>';
  }
  supplies.innerHTML = suppliesHtml;
}

// ============ 启动 ============

document.addEventListener('DOMContentLoaded', startPolling);
