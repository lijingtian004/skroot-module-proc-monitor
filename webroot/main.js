// main.js — Multi-page process monitor

let allEvents = [];
let allAlerts = [];
let allProcs = [];
let filteredProcs = [];
let currentProcCat = 'all';
let stats = { total: 0, alerts: 0, exec: 0, exit: 0 };
let currentPage = 'overview';
let pollTimer = null;
let chargingInfo = null;

// ============ Process Categories ============
const RISKY_NAMES = [
  'magisk', 'magiskd', 'su', 'frida', 'lsposed', 'lsposedd',
  'riru', 'zygisk', 'shamiko', 'xposed', 'edxposed',
  'kernelsu', 'apatch', 'strace', 'ltrace', 'gdb', 'gdbserver',
];
const SYSTEM_NAMES = [
  'system_server', 'init', 'zygote', 'zygote64', 'servicemanager',
  'binder', 'hwservicemanager', 'vndservicemanager', 'ueventd',
  'logd', 'lmkd', 'installd', 'tombstoned', 'crash_dump',
  'linker', 'linker64', 'app_process', 'heapprofd',
];
const SHELL_NAMES = ['sh', 'bash', 'logcat', 'adb', 'adbd', 'toybox', 'toybox64'];

function classifyProc(p) {
  const comm = (p.comm || '').toLowerCase();
  const cmdline = (p.cmdline || '').toLowerCase();
  const uid = p.uid;
  for (const name of RISKY_NAMES) {
    if (comm.includes(name) || cmdline.includes(name)) return 'risky';
  }
  if (uid === 0 || uid === 1000) {
    for (const name of SYSTEM_NAMES) { if (comm.includes(name)) return 'system'; }
    return 'system';
  }
  if (uid === 2000) return 'shell';
  if (uid >= 10000) return 'app';
  return 'service';
}

// ============ API ============
async function api(path, body = '') {
  try {
    // 先尝试 POST
    let resp = await fetch(new URL(path, window.location.href), { method: 'POST', body });
    if (resp.ok) return await resp.text();
    // POST 失败则回退 GET
    const url = body ? `${path}?limit=${body}` : path;
    resp = await fetch(new URL(url, window.location.href), { method: 'GET' });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return await resp.text();
  } catch (e) { console.error(`API [${path}]:`, e); return null; }
}

// ============ Data Fetch ============
async function fetchEvents() {
  const raw = await api('/api/events', '200');
  if (raw) try { allEvents = JSON.parse(raw); } catch (e) {}
}

async function fetchAlerts() {
  const raw = await api('/api/alerts', '100');
  if (raw) try { allAlerts = JSON.parse(raw); } catch (e) {}
}

async function fetchStats() {
  const raw = await api('/api/stats');
  if (raw) try {
    const s = JSON.parse(raw);
    stats.total = s.total_events || 0;
    stats.alerts = s.total_alerts || 0;
    updateStatsUI();
  } catch (e) {}
}

async function fetchProcs() {
  const raw = await api('/api/procs');
  if (raw) try {
    allProcs = JSON.parse(raw).map(p => ({ ...p, cat: classifyProc(p) }));
    updateProcCounts();
    if (currentPage === 'procs') filterProcs();
    if (currentPage === 'overview') updateOverviewSummary();
  } catch (e) {}
}

async function fetchCharging() {
  const raw = await api('/api/charging');
  if (raw) try {
    chargingInfo = JSON.parse(raw);
    if (currentPage === 'power') renderChargingInfo();
    if (currentPage === 'overview') updateOverviewPower();
  } catch (e) {}
}

let drainData = [];
let drainSysPower = 0;
let drainBatStatus = '';
let drainBatLevel = -1;
let drainBatCurrent = -1;
let drainBatVoltage = -1;
let drainBatTemp = -1;
let drainChargeType = '';
let drainChargerSpeed = '';
let drainMode = 'app'; // 'app' = per-app, 'system' = 整机电池输出

async function fetchDrain() {
  const raw = await api('/api/power-drain', '20');
  if (raw) try {
    const resp = JSON.parse(raw);
    // 兼容新格式: { system_power_mw, battery_status, apps: [...] }
    if (resp.apps) {
      drainData = resp.apps;
      drainSysPower = resp.system_power_mw || 0;
      drainBatStatus = resp.battery_status || '';
      drainBatLevel = resp.battery_level ?? -1;
      drainBatCurrent = resp.battery_current_ma ?? -1;
      drainBatVoltage = resp.battery_voltage_mv ?? -1;
      drainBatTemp = resp.battery_temp ?? -1;
      drainChargeType = resp.charge_type || '';
      drainChargerSpeed = resp.charger_speed || '';
    } else {
      // 旧格式 fallback: 直接是数组
      drainData = resp;
    }
    renderDrainInfo();
  } catch (e) {}
}

function toggleDrainMode() {
  drainMode = drainMode === 'app' ? 'system' : 'app';
  renderDrainInfo();
}

function renderDrainInfo() {
  const sum = document.getElementById('drainSummary');
  const list = document.getElementById('drainList');
  const toggle = document.getElementById('drainToggle');

  // 更新开关按钮文字
  if (toggle) {
    toggle.textContent = drainMode === 'app' ? '按应用估算' : '整机电池输出';
    toggle.className = drainMode === 'app' ? 'drain-toggle mode-app' : 'drain-toggle mode-sys';
  }
  // 显示/隐藏提示文字，按模式切换内容
  const note = document.getElementById('drainNote');
  if (note) {
    if (drainMode === 'app') {
      note.textContent = '⚠️ 功耗按 CPU 时间占比分摊实际电池功率，仅为估算值（不含屏幕/GPU/网络）';
      note.style.display = '';
    } else {
      note.textContent = '⚠️ 应用功耗 = 该 App 在前台时的电池功率平均值';
      note.style.display = '';
    }
  }

  // 按应用估算模式 和 整机电池输出模式 共用列表
  if (!drainData.length) {
    list.innerHTML = '<div class="empty-hint">暂无数据，等待首次采样...</div>';
    return;
  }

  // 汇总
  let totalCpu = 0, totalMem = 0, totalProcs = 0;
  drainData.forEach(a => { totalCpu += a.cpu_pct; totalMem += a.mem_mb; totalProcs += a.procs; });

  if (drainMode === 'system') {
    // 整机模式：顶栏显示实际电池功率 + 电量状态温度
    const sysW = (drainSysPower / 1000).toFixed(2);
    const statusMap = { 'Charging': '充电中', 'Discharging': '放电中', 'Full': '已充满', 'Not charging': '未充电' };
    const statusCN = statusMap[drainBatStatus] || drainBatStatus || '--';
    const tempC = drainBatTemp > 0 ? (drainBatTemp / 10).toFixed(1) + '°C' : '--';
    sum.innerHTML = `
      <div class="drain-sum-grid">
        <div class="drain-sum-item"><span class="drain-sum-val">${sysW}W</span><span class="drain-sum-label">电池输出</span></div>
        <div class="drain-sum-item"><span class="drain-sum-val">${drainBatLevel >= 0 ? drainBatLevel + '%' : '--'}</span><span class="drain-sum-label">电量</span></div>
        <div class="drain-sum-item"><span class="drain-sum-val">${statusCN}</span><span class="drain-sum-label">状态</span></div>
        <div class="drain-sum-item"><span class="drain-sum-val">${tempC}</span><span class="drain-sum-label">温度</span></div>
      </div>`;
  } else {
    // 应用估算模式
    sum.innerHTML = `
      <div class="drain-sum-grid">
        <div class="drain-sum-item"><span class="drain-sum-val">${drainData.length}</span><span class="drain-sum-label">应用</span></div>
        <div class="drain-sum-item"><span class="drain-sum-val">${totalCpu.toFixed(1)}%</span><span class="drain-sum-label">CPU</span></div>
        <div class="drain-sum-item"><span class="drain-sum-val">${totalMem.toFixed(0)}M</span><span class="drain-sum-label">内存</span></div>
        <div class="drain-sum-item"><span class="drain-sum-val">${totalProcs}</span><span class="drain-sum-label">进程</span></div>
      </div>`;
  }

  // 列表（两种模式共用，功耗字段不同）
  // 按当前模式重新排序
  if (drainMode === 'system') {
    // 整机模式：只显示曾在前台的 App（avg_battery_mw > 0）
    drainData.sort((a, b) => (b.avg_battery_mw || 0) - (a.avg_battery_mw || 0));
    const filtered = drainData.filter(a => (a.avg_battery_mw || 0) > 0);
    if (filtered.length) drainData = filtered;
  }
  let html = '';
  drainData.forEach((a, i) => {
    const mw = drainMode === 'system' ? (a.avg_battery_mw || 0) : (a.power_mw || 0);
    const color = mw > 1500 ? 'var(--red)' : mw > 500 ? 'var(--amber)' : 'var(--green)';
    const name = esc(a.label || a.package || `UID ${a.uid}`);
    const watts = (mw / 1000).toFixed(2);
    html += `<div class="drain-row" onclick="showDrainDetail(${i})">
      <div class="drain-rank">${i + 1}</div>
      <div class="drain-info">
        <div class="drain-name">${name}</div>
        <div class="drain-stats">
          <span>CPU ${a.cpu_pct.toFixed(1)}%</span>
          <span>内存 ${a.mem_mb}M</span>
          <span>${a.procs}进程</span>
        </div>
      </div>
      <div class="drain-score" style="color:${color}">${watts}<span style="font-size:9px">W</span></div>
    </div>`;
  });
  list.innerHTML = html;
}

function showDrainDetail(i) {
  const a = drainData[i];
  if (!a) return;
  const overlay = document.getElementById('modalOverlay');
  const body = document.getElementById('modalBody');
  const title = document.getElementById('modalTitle');
  title.textContent = a.label || a.package || `UID ${a.uid}`;
  body.innerHTML = `
    <div class="detail-grid">
      <div class="detail-row"><span class="detail-label">UID</span><span class="detail-value">${a.uid}</span></div>
      <div class="detail-row"><span class="detail-label">包名</span><span class="detail-value">${esc(a.package || '--')}</span></div>
      <div class="detail-row"><span class="detail-label">应用名</span><span class="detail-value">${esc(a.label)}</span></div>
      <div class="detail-row"><span class="detail-label">CPU 占用</span><span class="detail-value">${a.cpu_pct.toFixed(1)}%</span></div>
      <div class="detail-row"><span class="detail-label">内存占用</span><span class="detail-value">${a.mem_mb} MB</span></div>
      <div class="detail-row"><span class="detail-label">IO 总量</span><span class="detail-value">${a.io_mb} MB</span></div>
      <div class="detail-row"><span class="detail-label">进程数</span><span class="detail-value">${a.procs}</span></div>
      <div class="detail-row"><span class="detail-label">功耗(CPU占比)</span><span class="detail-value">${(a.power_mw/1000).toFixed(2)} W</span></div>
      <div class="detail-row"><span class="detail-label">功耗(期间均值)</span><span class="detail-value">${((a.avg_battery_mw||0)/1000).toFixed(2)} W</span></div>
    </div>`;
  overlay.classList.add('show');
}

async function manualScan() {
  await api('/api/scan');
  setTimeout(pollAll, 300);
}

// ============ Page Navigation ============
function switchPage(page) {
  currentPage = page;
  document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.id === `page-${page}`));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.toggle('active', b.dataset.page === page));
  if (page === 'overview') { updateStatsUI(); updateOverviewAlerts(); updateOverviewSummary(); updateOverviewPower(); }
  if (page === 'procs') { fetchProcs(); filterProcs(); }
  if (page === 'alerts') renderAlertList();
  if (page === 'log') filterHistory();
  if (page === 'power') fetchCharging();
  if (page === 'drain') fetchDrain();
}

// ============ UI Updates ============
function updateStatsUI() {
  document.getElementById('statTotal').textContent = fmtN(stats.total);
  document.getElementById('statAlerts').textContent = fmtN(stats.alerts);
  document.getElementById('statExec').textContent = fmtN(stats.total - stats.exit - stats.alerts);
  document.getElementById('statExit').textContent = fmtN(stats.exit || 0);
  const ab = document.getElementById('navAlertBadge');
  if (ab) {
    if (stats.alerts > 0) { ab.style.display = 'block'; ab.textContent = stats.alerts; }
    else { ab.style.display = 'none'; }
  }
}

function updateOverviewAlerts() {
  const el = document.getElementById('overviewAlerts');
  const count = document.getElementById('overviewAlertCount');
  count.textContent = allAlerts.length;
  if (allAlerts.length === 0) {
    el.innerHTML = '<div class="empty-hint">暂无告警</div>';
    return;
  }
  const recent = allAlerts.slice(0, 5);
  el.innerHTML = recent.map(ev => `
    <div class="event-item alert-item" onclick='showDetail(${JSON.stringify(ev).replace(/'/g, "&#39;")})'>
      <span class="event-icon alert">⚠</span>
      <div class="event-body">
        <div class="event-main"><span class="comm">${esc(ev.comm)}</span><span class="pid">PID ${ev.pid}</span></div>
        <div class="event-reason">${esc(ev.reason || '')}</div>
      </div>
      <span class="event-time">${fmtTime(ev.ts)}</span>
    </div>
  `).join('');
}

function updateOverviewSummary() {
  const counts = { system: 0, service: 0, app: 0, shell: 0, risky: 0 };
  for (const p of allProcs) counts[p.cat]++;
  document.getElementById('sumSystem').textContent = counts.system;
  document.getElementById('sumService').textContent = counts.service;
  document.getElementById('sumApp').textContent = counts.app;
  document.getElementById('sumShell').textContent = counts.shell;
  document.getElementById('sumRisky').textContent = counts.risky;
}

function updateOverviewPower() {
  if (!chargingInfo) return;
  document.getElementById('miniBatt').textContent = chargingInfo.battery_level >= 0 ? chargingInfo.battery_level : '--';
  document.getElementById('miniBattStatus').textContent = chargingInfo.battery_status || '--';
}

function updateProcCounts() {
  const counts = { all: allProcs.length, system: 0, service: 0, app: 0, shell: 0, risky: 0 };
  for (const p of allProcs) counts[p.cat]++;
  document.querySelectorAll('.cat-btn').forEach(btn => {
    const cat = btn.dataset.cat;
    const cs = btn.querySelector('.cat-count');
    if (cs) cs.textContent = counts[cat] || 0;
  });
  const count = document.getElementById('procCount');
  if (count) count.textContent = `${counts.all} 个进程`;
  const pb = document.getElementById('navProcBadge');
  if (pb) { pb.style.display = 'block'; pb.textContent = counts.all; }
}

// ============ Render: Events ============
function renderEventItem(ev, isNew) {
  const div = document.createElement('div');
  const cls = ev.type === 0 ? 'exec' : ev.type === 1 ? 'exit' : 'alert';
  div.className = `event-item ${cls}-item${isNew ? ' new' : ''}`;
  div.onclick = () => showDetail(ev);
  const icon = ev.type === 0 ? '▶' : ev.type === 1 ? '■' : '⚠';
  const reason = ev.reason ? `<div class="event-reason">⚠ ${esc(ev.reason)}</div>` : '';
  const cmd = ev.cmdline ? esc(ev.cmdline.substring(0, 80)) : '';
  div.innerHTML = `
    <span class="event-icon ${cls}">${icon}</span>
    <div class="event-body">
      <div class="event-main"><span class="comm">${esc(ev.comm)}</span><span class="pid">PID ${ev.pid}</span></div>
      <div class="event-sub">${cmd || `PPID ${ev.ppid} · ${uidName(ev.uid)}`}</div>
      ${reason}
    </div>
    <span class="event-time">${fmtTime(ev.ts)}</span>
  `;
  return div;
}

function renderAlertList() {
  const list = document.getElementById('alertList');
  const summary = document.getElementById('alertSummary');
  if (allAlerts.length === 0) {
    list.innerHTML = '<div class="empty-state"><span class="empty-icon">▪</span><p>未检测到可疑进程</p></div>';
    summary.textContent = '无告警';
    return;
  }
  summary.textContent = `${allAlerts.length} 条告警`;
  list.innerHTML = '';
  for (const ev of allAlerts.slice(0, 200)) list.appendChild(renderEventItem(ev, false));
}

function renderHistoryList(events) {
  const list = document.getElementById('historyList');
  list.innerHTML = '';
  if (events.length === 0) { list.innerHTML = '<div class="loading">无匹配记录</div>'; return; }
  for (const ev of events.slice(0, 200)) list.appendChild(renderEventItem(ev, false));
}

// ============ Render: Procs ============
function renderProcItem(p) {
  const div = document.createElement('div');
  div.className = 'event-item';
  div.onclick = () => showProcDetail(p);
  const cmd = p.cmdline ? esc(p.cmdline.substring(0, 60)) : '';
  div.innerHTML = `
    <div class="event-body">
      <div class="event-main"><span class="comm">${esc(p.comm)}</span><span class="pid">PID ${p.pid}</span></div>
      <div class="event-sub">${cmd || `PPID ${p.ppid} · ${uidName(p.uid)}`}</div>
    </div>
  `;
  return div;
}

function renderProcsList(procs) {
  const list = document.getElementById('procList');
  list.innerHTML = '';
  if (procs.length === 0) { list.innerHTML = '<div class="loading">无进程数据</div>'; return; }
  for (const p of procs.slice(0, 500)) list.appendChild(renderProcItem(p));
}

// ============ Filter ============
function filterProcs() {
  const kw = document.getElementById('procSearchInput').value.toLowerCase();
  filteredProcs = allProcs;
  if (currentProcCat !== 'all') filteredProcs = filteredProcs.filter(p => p.cat === currentProcCat);
  if (kw) filteredProcs = filteredProcs.filter(p =>
    p.comm.toLowerCase().includes(kw) || String(p.pid).includes(kw) || (p.cmdline && p.cmdline.toLowerCase().includes(kw))
  );
  const count = document.getElementById('procCount');
  if (count) count.textContent = kw ? `${filteredProcs.length} / ${allProcs.length}` : `${allProcs.length} 个进程`;
  renderProcsList(filteredProcs);
}

function filterHistory() {
  const kw = document.getElementById('searchInput').value.toLowerCase();
  const tf = document.getElementById('filterType').value;
  let filtered = allEvents;
  if (tf !== 'all') { const m = { exec: 0, exit: 1, alert: 2 }; filtered = filtered.filter(e => e.type === m[tf]); }
  if (kw) filtered = filtered.filter(e => e.comm.toLowerCase().includes(kw) || String(e.pid).includes(kw) || (e.cmdline && e.cmdline.toLowerCase().includes(kw)));
  renderHistoryList(filtered);
}

function switchProcCat(cat) {
  currentProcCat = cat;
  document.querySelectorAll('.cat-btn').forEach(b => b.classList.toggle('active', b.dataset.cat === cat));
  filterProcs();
}

// ============ Modals ============
function showDetail(ev) {
  const overlay = document.getElementById('modalOverlay');
  const body = document.getElementById('modalBody');
  const title = document.getElementById('modalTitle');
  const typeLabel = ev.type === 0 ? '新建' : ev.type === 1 ? '退出' : '告警';
  title.textContent = `${ev.comm} — ${typeLabel}`;
  const rows = [['类型', typeLabel], ['时间', fmtTimestamp(ev.ts)], ['PID', ev.pid], ['PPID', ev.ppid], ['UID', `${ev.uid} (${uidName(ev.uid)})`], ['名称', ev.comm]];
  if (ev.cmdline) rows.push(['命令行', ev.cmdline]);
  if (ev.reason) rows.push(['原因', ev.reason]);
  body.innerHTML = rows.map(([l, v]) => `<div class="detail-row"><span class="detail-label">${esc(l)}</span><span class="detail-value">${esc(String(v))}</span></div>`).join('');
  overlay.classList.add('show');
}

function showProcDetail(p) {
  const overlay = document.getElementById('modalOverlay');
  const body = document.getElementById('modalBody');
  const title = document.getElementById('modalTitle');
  title.textContent = `${p.comm} — 进程`;
  const rows = [['PID', p.pid], ['PPID', p.ppid], ['UID', `${p.uid} (${uidName(p.uid)})`], ['名称', p.comm]];
  if (p.cmdline) rows.push(['命令行', p.cmdline]);
  body.innerHTML = rows.map(([l, v]) => `<div class="detail-row"><span class="detail-label">${esc(l)}</span><span class="detail-value">${esc(String(v))}</span></div>`).join('');
  overlay.classList.add('show');
}

function closeModal() { document.getElementById('modalOverlay').classList.remove('show'); }

// ============ Charging Render ============
function renderChargingInfo() {
  if (!chargingInfo) return;
  const ov = document.getElementById('chargingOverview');
  const lvl = chargingInfo.battery_level >= 0 ? chargingInfo.battery_level : '--';
  const status = chargingInfo.battery_status || '未知';
  const speed = chargingInfo.charger_speed || 'unknown';
  ov.innerHTML = `
    <div class="charge-big-status">${esc(status)}</div>
    <div class="charge-level">
      <div class="charge-level-num">${lvl}<span style="font-size:20px;color:var(--text-3)">%</span></div>
      <div class="charge-level-bar"><div class="charge-level-fill" style="width:${lvl}%"></div></div>
    </div>
    <div class="charge-speed-label">${esc(speed)} 充电</div>
    ${chargingInfo.battery_health_pct ? `
    <div class="charge-health-bar">
      <div class="charge-health-label">电池健康</div>
      <div class="charge-health-value">${chargingInfo.battery_health_pct.toFixed(1)}%</div>
      <div class="charge-health-track"><div class="charge-health-fill" style="width:${chargingInfo.battery_health_pct}%"></div></div>
    </div>` : ''}
  `;
  const det = document.getElementById('chargingDetails');
  const rows = [];
  if (chargingInfo.battery_temp > 0) rows.push(['温度', (chargingInfo.battery_temp / 10).toFixed(1) + ' °C']);
  if (chargingInfo.battery_voltage_mv > 0) rows.push(['电压', chargingInfo.battery_voltage_mv + ' mV']);
  if (chargingInfo.battery_current_ma !== -1) rows.push(['电流', chargingInfo.battery_current_ma + ' mA']);
  if (chargingInfo.charge_type && chargingInfo.charge_type !== 'N/A') rows.push(['充电类型', chargingInfo.charge_type]);
  if (chargingInfo.battery_technology) rows.push(['电池技术', chargingInfo.battery_technology]);
  if (chargingInfo.battery_health) rows.push(['健康状态', chargingInfo.battery_health]);
  if (rows.length) {
    det.innerHTML = `<div class="section-title">详细信息</div><div class="detail-grid">${rows.map(([l, v]) => `<div class="detail-row"><span class="detail-label">${esc(l)}</span><span class="detail-value">${esc(v)}</span></div>`).join('')}</div>`;
  }
  const sup = document.getElementById('chargingSupplies');
  if (chargingInfo.supplies && chargingInfo.supplies.length) {
    let html = '<div class="section-title">电源设备</div>';
    for (const s of chargingInfo.supplies) {
      html += `<div class="supply-card">
        <div class="supply-header">${esc(s.name)} <span class="supply-type-badge">${esc(s.type)}</span></div>
        <div class="supply-rows">
          ${s.status ? `<div class="supply-kv"><span class="k">状态</span><span class="v">${esc(s.status)}</span></div>` : ''}
          ${s.capacity ? `<div class="supply-kv"><span class="k">电量</span><span class="v">${s.capacity}%</span></div>` : ''}
          ${s.temp ? `<div class="supply-kv"><span class="k">温度</span><span class="v">${(s.temp/10).toFixed(1)}°C</span></div>` : ''}
          ${s.voltage_uv ? `<div class="supply-kv"><span class="k">电压</span><span class="v">${(s.voltage_uv/1000).toFixed(0)}mV</span></div>` : ''}
        </div>
      </div>`;
    }
    sup.innerHTML = html;
  }
}

// ============ Polling ============
async function pollAll() {
  await Promise.all([fetchEvents(), fetchAlerts(), fetchStats(), fetchProcs(), fetchCharging()]);
  const dot = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  dot.classList.add('online');
  text.textContent = '在线';
  if (currentPage === 'overview') { updateStatsUI(); updateOverviewAlerts(); updateOverviewSummary(); updateOverviewPower(); }
  if (currentPage === 'alerts') renderAlertList();
  if (currentPage === 'log') filterHistory();
}

function startPolling() {
  pollAll();
  pollTimer = setInterval(pollAll, 5000);
}

// ============ Helpers ============
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function fmtN(n) { return n >= 10000 ? (n / 1000).toFixed(1) + 'k' : String(n); }
function fmtTime(ts) { const d = new Date(ts); const p = n => String(n).padStart(2, '0'); return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`; }
function fmtTimestamp(ts) { const d = new Date(ts); const p = n => String(n).padStart(2, '0'); return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds())}`; }
function uidName(uid) { if (uid === 0) return 'root'; if (uid >= 10000 && uid < 20000) return `u${Math.floor(uid/10000)-1}`; if (uid === 2000) return 'shell'; return `uid:${uid}`; }

// ============ Init ============
document.addEventListener('DOMContentLoaded', startPolling);
