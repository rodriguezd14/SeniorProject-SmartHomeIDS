const state = {
  devices: [
  ],
  alerts: [
  ],
  packets: [],
  currentSection: 'dashboard',
  packetsAnalyzed: 120000,
  alertsToday: 8,
  trafficSeries: { inbound: [], outbound: [] },
  liveAlertTimer: null,
  modalAlert: null,
  iconFilter: null,
};

const refs = {
  pageTitle: document.getElementById('pageTitle'),
  navLinks: [...document.querySelectorAll('.nav-link')],
  sections: [...document.querySelectorAll('.page-section')],
  clockDisplay: document.getElementById('clockDisplay'),
  bellBadge: document.getElementById('bellBadge'),
  navAlertBadge: document.getElementById('navAlertBadge'),
  networkPill: document.getElementById('networkPill'),
  networkStatusText: document.getElementById('networkStatusText'),
  recentAlerts: document.getElementById('recentAlerts'),
  deviceCards: document.getElementById('deviceCards'),
  deviceTableBody: document.getElementById('deviceTableBody'),
  deviceSearch: document.getElementById('deviceSearch'),
  packetLogBody: document.getElementById('packetLogBody'),
  alertsList: document.getElementById('alertsList'),
  severityFilter: document.getElementById('severityFilter'),
  statusFilter: document.getElementById('statusFilter'),
  toast: document.getElementById('toast'),
  alertModal: document.getElementById('alertModal'),
  modalTitle: document.getElementById('modalTitle'),
  modalBody: document.getElementById('modalBody'),
  saveSettingsBtn: document.getElementById('saveSettingsBtn'),
  thresholdSlider: document.getElementById('thresholdSlider'),
  thresholdLabel: document.getElementById('thresholdLabel'),
  menuToggle: document.getElementById('menuToggle'),
  sidebar: document.getElementById('sidebar'),
};

function rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function formatTime(date = new Date()) { return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
function formatDate(date = new Date()) { return date.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' }); }
function badgeClass(sev) { return sev === 'HIGH' ? 'severity-high' : sev === 'MEDIUM' ? 'severity-medium' : 'severity-low'; }

function updateClock() {
  refs.clockDisplay.textContent = `${formatDate()} • ${formatTime()}`;
}

function updateSidebarStatus() {
  const hasHigh = state.alerts.some(a => a.status === 'ACTIVE' && a.severity === 'HIGH');
  refs.networkStatusText.textContent = hasHigh ? 'Network: Threat Detected' : 'Network: Protected';
  refs.networkPill.querySelector('.status-dot').className = `status-dot ${hasHigh ? 'danger' : 'success'}`;
  document.getElementById('statStatus').textContent = hasHigh ? 'THREAT DETECTED' : 'NORMAL';
  document.getElementById('statStatusSub').textContent = hasHigh ? 'Suspicious traffic is active' : 'All traffic appears safe';
  document.getElementById('statDevices').textContent = String(state.devices.length);
  document.getElementById('statAlerts').textContent = String(state.alertsToday);
  document.getElementById('statPackets').textContent = String(state.packetsAnalyzed.toLocaleString());
}

function renderRecentAlerts() {
  const latest = [...state.alerts].sort((a, b) => b.id - a.id).slice(0, 8);
  refs.recentAlerts.innerHTML = latest.map(alert => `
    <article class="alert-item">
      <span class="severity-badge ${badgeClass(alert.severity)}">${alert.severity}</span>
      <strong>${alert.title}</strong>
      <p>${alert.description}</p>
      <div class="alert-meta">
        <span>${alert.sourceIp}</span>
        <span>${alert.time}</span>
      </div>
    </article>
  `).join('');
}

function renderDevices() {
  refs.deviceCards.innerHTML = state.devices.slice(0, 8).map(device => `
    <article class="device-card">
      <div style="display:flex;justify-content:space-between;align-items:center; gap:8px;">
        <div>
          <h4>${device.icon} ${device.name}</h4>
          <p class="mono">${device.ip}</p>
        </div>
        <span class="status-dot ${device.status === 'Suspicious' ? 'danger' : device.status === 'Warning' ? 'warning' : 'success'}"></span>
      </div>
      <p>${device.mac}</p>
      <div class="status-row"><span>Last seen</span> <strong>${device.lastSeen}</strong></div>
    </article>
  `).join('');

  const query = refs.deviceSearch.value.toLowerCase();
  const rows = state.devices.filter(device => {
    const matchesSearch = `${device.name} ${device.ip}`.toLowerCase().includes(query);
    const matchesIcon = state.iconFilter ? device.icon === state.iconFilter : true;
    return matchesSearch && matchesIcon;
  });

  refs.deviceTableBody.innerHTML = rows.map(device => `
    <tr class="${device.status === 'Blocked' ? 'blocked-row' : ''}">
      <td>${device.icon}</td>
      <td>${device.name}</td>
      <td class="mono">${device.ip}</td>
      <td class="mono">${device.mac}</td>
      <td>${device.firstSeen}</td>
      <td>${device.lastSeen}</td>
      <td><span class="status-pill ${device.status === 'Blocked' ? 'blocked' : device.status === 'Suspicious' ? 'suspicious' : device.status === 'Warning' ? 'warning' : 'normal'}">${device.status}</span></td>
      <td>
        <div class="action-group">
          <button class="outline-btn danger" onclick="blockDevice(${device.id})">Block Device</button>
          <button class="outline-btn" onclick="inspectDevice(${device.id})">Inspect</button>
        </div>
      </td>
    </tr>
  `).join('');
}

function filterByIcon(icon) {
    if (state.iconFilter === icon) {
        state.iconFilter = null;
    } else {
        state.iconFilter = icon;
    }
    // Update legend item highlight
    document.querySelectorAll('.legend-item').forEach(item => {
        item.classList.toggle('legend-active', item.dataset.icon === state.iconFilter);
    });
    renderDevices();
}

function renderAlerts() {
  const severity = refs.severityFilter.value;
  const status = refs.statusFilter.value;
  const filtered = state.alerts.filter(alert => (severity === 'ALL' || alert.severity === severity) && (status === 'ALL' || alert.status === status));
  refs.alertsList.innerHTML = filtered.map(alert => `
    <article class="alert-card ${alert.status === 'RESOLVED' ? 'resolved' : ''}">
      <div class="alert-card-head">
        <div>
          <span class="severity-badge ${badgeClass(alert.severity)}">${alert.severity}</span>
          <h4>${alert.title}</h4>
        </div>
        <span class="pill ${alert.status === 'RESOLVED' ? 'info' : 'warning'}">${alert.status}</span>
      </div>
      <p>${alert.description}</p>
      <p><strong>Source:</strong> ${alert.sourceIp} • <strong>Target:</strong> ${alert.target}</p>
      <p>${alert.time}</p>
      <div class="alert-actions">
        <button class="outline-btn ${alert.status === 'RESOLVED' ? 'disabled' : ''}" onclick="resolveAlert(${alert.id})">${alert.status === 'RESOLVED' ? 'Resolved ✓' : 'Mark Resolved'}</button>
        <button class="outline-btn" onclick="openModal(${alert.id})">Investigate</button>
      </div>
    </article>
  `).join('');
}

function updateBadges() {
  const unresolved = state.alerts.filter(a => a.status === 'ACTIVE').length;
  refs.bellBadge.textContent = String(unresolved);
  refs.navAlertBadge.textContent = String(unresolved);
}

function renderPacketLog() {
  const rows = state.packets.slice(-50);
  refs.packetLogBody.innerHTML = rows.map(entry => `
    <tr>
      <td>${entry.time}</td>
      <td class="mono">${entry.source}</td>
      <td class="mono">${entry.destination}</td>
      <td>${entry.protocol}</td>
      <td>${entry.size} KB</td>
      <td><span class="status-pill ${entry.status === 'BLOCKED' ? 'suspicious' : entry.status === 'SUSPICIOUS' ? 'warning' : 'normal'}">${entry.status}</span></td>
    </tr>
  `).join('');
}

function updateCharts() {
  if (window.trafficChart) {
    trafficChart.data.labels = state.trafficSeries.inbound.map((_, i) => `${i}s`);
    trafficChart.data.datasets[0].data = state.trafficSeries.inbound;
    trafficChart.data.datasets[1].data = state.trafficSeries.outbound;
    trafficChart.update();
  }
  if (window.hourlyTrafficChart) {
    hourlyTrafficChart.data.datasets[0].data = [58, 63, 72, 70, 68, 74, 81, 79, 83, 88, 91, 96];
    hourlyTrafficChart.data.datasets[1].data = [42, 48, 52, 55, 50, 57, 61, 64, 67, 69, 72, 75];
    hourlyTrafficChart.update();
  }
  if (window.protocolChart) {
    protocolChart.data.datasets[0].data = [45, 30, 10, 10, 5];
    protocolChart.update();
  }
}

function simulateTraffic() {
  const inbound = rand(18, 42);
  const outbound = rand(10, 28);
  state.trafficSeries.inbound.push(inbound);
  state.trafficSeries.outbound.push(outbound);
  if (state.trafficSeries.inbound.length > 60) state.trafficSeries.inbound.shift();
  if (state.trafficSeries.outbound.length > 60) state.trafficSeries.outbound.shift();

  state.packetsAnalyzed += rand(120, 380);
  state.alertsToday += Math.random() > 0.82 ? 1 : 0;
  const src = `192.168.1.${rand(10, 30)}`;
  const dst = `192.168.1.${rand(1, 9)}`;
  const protocols = ['TCP', 'UDP', 'ICMP', 'HTTP'];
  const statuses = ['ALLOWED', 'BLOCKED', 'SUSPICIOUS'];
  state.packets.push({ time: formatTime(), source: src, destination: dst, protocol: protocols[rand(0, 3)], size: rand(1, 12), status: statuses[rand(0, 2)] });
  if (state.packets.length > 50) state.packets.shift();

  updateCharts();
  renderPacketLog();
  updateSidebarStatus();
  renderRecentAlerts();
  updateBadges();
  renderDevices();
}

function generateAlert() {
  const templates = [
    { title: 'Port Scan Detected', severity: 'HIGH', desc: 'The gateway detected aggressive port scanning from an untrusted source.', src: '198.51.100.10', target: 'Wi-Fi Router' },
    { title: 'Unknown Device Attempting Connection', severity: 'MEDIUM', desc: 'A host attempted to access reserved addresses on the LAN.', src: '192.168.1.21', target: 'LAN Segment' },
    { title: 'New Device Connected', severity: 'LOW', desc: 'A previously unseen endpoint joined the network and requested DHCP.', src: '192.168.1.23', target: 'Unknown Device' },
    { title: 'Brute Force Attempt', severity: 'HIGH', desc: 'Repeated password attempts were recorded against a local admin interface.', src: '203.0.113.88', target: 'Smart Doorbell' },
  ];
  const item = templates[rand(0, templates.length - 1)];
  state.alerts.unshift({ id: Date.now(), title: item.title, description: item.desc, severity: item.severity, status: 'ACTIVE', sourceIp: item.src, target: item.target, time: formatTime() });
  state.alerts = state.alerts.slice(0, 18);
  state.alertsToday += 1;
  renderRecentAlerts();
  renderAlerts();
  updateBadges();
  updateSidebarStatus();
  showToast(`${item.title} • ${item.severity} severity alert triggered`);
}

function resolveAlert(id) {
  state.alerts = state.alerts.map(a => a.id === id ? { ...a, status: 'RESOLVED' } : a);
  renderRecentAlerts();
  renderAlerts();
  updateBadges();
  updateSidebarStatus();
}

function openModal(id) {
  const alert = state.alerts.find(a => a.id === id);
  state.modalAlert = alert;
  refs.modalTitle.textContent = `${alert.title} — ${alert.severity}`;
  refs.modalBody.textContent = `${alert.description} The source host ${alert.sourceIp} attempted access against ${alert.target}. This simulation details a live threat signal gathered from the IDS feed.`;
  refs.alertModal.classList.add('open');
}

function closeModal() {
  refs.alertModal.classList.remove('open');
}

function blockDevice(id) {
  state.devices = state.devices.map(device => device.id === id ? { ...device, status: 'Blocked' } : device);
  renderDevices();
}

function inspectDevice(id) {
  const device = state.devices.find(d => d.id === id);
  alert(`Inspecting ${device.name} at ${device.ip}`);
}

function switchSection(section) {
  state.currentSection = section;
  refs.navLinks.forEach(link => link.classList.toggle('active', link.dataset.section === section));
  document.querySelectorAll('.top-tab').forEach(tab => tab.classList.toggle('active', tab.dataset.section === section));
  refs.sections.forEach(panel => panel.classList.toggle('active', panel.id === `${section}Section`));
  refs.pageTitle.textContent = section.charAt(0).toUpperCase() + section.slice(1);
  refs.sidebar.classList.remove('open');
}

function showToast(msg) {
  refs.toast.textContent = msg;
  refs.toast.classList.add('show');
  clearTimeout(showToast.timeout);
  showToast.timeout = setTimeout(() => refs.toast.classList.remove('show'), 4000);
}

function initCharts() {
  const trafficCtx = document.getElementById('trafficChart');
  const hourlyCtx = document.getElementById('hourlyTrafficChart');
  const protocolCtx = document.getElementById('protocolChart');

  window.trafficChart = new Chart(trafficCtx, {
    type: 'line',
    data: {
      labels: Array.from({ length: 60 }, (_, i) => `${i}s`),
      datasets: [
        { label: 'Inbound', data: Array.from({ length: 60 }, () => rand(15, 35)), borderColor: '#00D4FF', backgroundColor: 'rgba(0,212,255,0.08)', fill: true, tension: 0.35 },
        { label: 'Outbound', data: Array.from({ length: 60 }, () => rand(8, 24)), borderColor: '#00FF88', backgroundColor: 'rgba(0,255,136,0.05)', fill: true, tension: 0.35 },
      ],
    },
    options: { responsive: true, animation: false, plugins: { legend: { labels: { color: '#B8C8E0' } } }, scales: { x: { ticks: { color: '#B8C8E0' }, grid: { color: 'rgba(255,255,255,0.05)' } }, y: { ticks: { color: '#B8C8E0' }, grid: { color: 'rgba(255,255,255,0.08)' } } } },
  });

  window.hourlyTrafficChart = new Chart(hourlyCtx, {
    type: 'bar',
    data: {
      labels: ['00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11'],
      datasets: [
        { label: 'Inbound', data: [50, 52, 55, 57, 60, 65, 66, 68, 72, 78, 82, 86], backgroundColor: 'rgba(0,212,255,0.65)' },
        { label: 'Outbound', data: [35, 36, 39, 42, 45, 48, 50, 53, 56, 60, 62, 64], backgroundColor: 'rgba(0,255,136,0.65)' },
      ],
    },
    options: { responsive: true, plugins: { legend: { labels: { color: '#B8C8E0' } } }, scales: { x: { ticks: { color: '#B8C8E0' }, grid: { color: 'rgba(255,255,255,0.05)' } }, y: { ticks: { color: '#B8C8E0' }, grid: { color: 'rgba(255,255,255,0.08)' } } } },
  });

  window.protocolChart = new Chart(protocolCtx, {
    type: 'doughnut',
    data: {
      labels: ['TCP', 'UDP', 'ICMP', 'HTTP', 'Other'],
      datasets: [{ data: [45, 30, 10, 10, 5], backgroundColor: ['#00D4FF', '#00FF88', '#FFD600', '#FF3B3B', '#B8C8E0'] }],
    },
    options: { responsive: true, plugins: { legend: { labels: { color: '#B8C8E0' } } } },
  });
}

function initEvents() {
  refs.navLinks.forEach(link => link.addEventListener('click', (e) => { e.preventDefault(); switchSection(link.dataset.section); }));
  document.querySelectorAll('.top-tab').forEach(tab => tab.addEventListener('click', () => switchSection(tab.dataset.section)));
  refs.deviceSearch.addEventListener('input', renderDevices);
  refs.severityFilter.addEventListener('change', renderAlerts);
  refs.statusFilter.addEventListener('change', renderAlerts);
  refs.saveSettingsBtn.addEventListener('click', () => showToast('Settings saved. IDS monitoring configuration updated.'));
  refs.thresholdSlider.addEventListener('input', () => { refs.thresholdLabel.textContent = `${refs.thresholdSlider.value} MB/s`; });
  document.querySelectorAll('.chip').forEach(chip => chip.addEventListener('click', () => {
    document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
  }));
  refs.menuToggle.addEventListener('click', () => refs.sidebar.classList.toggle('open'));
  document.getElementById('closeModal').addEventListener('click', closeModal);
  refs.alertModal.addEventListener('click', (e) => { if (e.target === refs.alertModal) closeModal(); });
  document.getElementById('bellBtn').addEventListener('click', () => switchSection('alerts'));
}

async function loadPcapData() {

    const response = await fetch("/api/traffic");

    const data = await response.json();

    state.packets = data.packets;
    state.packetsAnalyzed = data.packet_count;

    // Populate devices from API data
    state.devices = data.devices.map((ip, index) => {
        let icon = '💻';
        let name = `Host-${index + 1}`;

        if (ip === '192.168.174.129') {
            icon = '🖥️'; name = 'This Machine';
        } else if (ip.endsWith('.1')) {
            icon = '📡'; name = 'Gateway/Router';
        } else if (ip.endsWith('.2')) {
            icon = '🔗'; name = 'DNS Server';
        } else if (ip.startsWith('239.') || ip.startsWith('255.')) {
            icon = '📢'; name = 'Multicast';
        } else if (!ip.startsWith('192.168.')) {
            icon = '🌍'; name = `External-${index + 1}`;
        }

        return {
            id: index,
            name: name,
            ip: ip,
            mac: 'N/A',
            icon: icon,
            status: 'Normal',
            firstSeen: formatTime(),
            lastSeen: formatTime(),
        };
    });

    // Calculate total KB for this batch and push into the Live Network Chart in the Dashboard
    const totalKB = data.packets.reduce((sum, pkt) => sum + pkt.size, 0);
    const inbound = parseFloat(totalKB.toFixed(2));
    const outbound = parseFloat((totalKB * 0.6).toFixed(2));

    state.trafficSeries.inbound.push(inbound);
    state.trafficSeries.outbound.push(outbound);

    // Keep the chart window to the last 60 data points
    if (state.trafficSeries.inbound.length > 60) state.trafficSeries.inbound.shift();
    if (state.trafficSeries.outbound.length > 60) state.trafficSeries.outbound.shift();

    updateCharts();
    renderPacketLog();
    renderDevices();
    updateSidebarStatus();

    document.getElementById("statPackets").textContent =
        data.packet_count.toLocaleString();

}

async function loadAlerts() {
	const response = await fetch("/api/alerts");
	const data = await response.json();

	//Onlt ADD alerts we haven't seen yet - never overwrite existine ones
	//This preserves any "Mark Resolved" clicks the user already made,
	// instead of wiping them out on the next poll
	data.alerts.forEach(incoming => {
		const alreadyExists = state.alerts.some(a => a.id === incoming.id);
		if (!alreadyExists) {
			state.alerts.unshift(incoming);
		}
	});

	state.alerts = state.alerts.slice(0, 50);

	renderRecentAlerts();
	renderAlerts();
	updateBadges();
	updatesSidebarStatus();
}

function init() {
  initCharts();
  initEvents();
  updateClock();
  setInterval(updateClock, 1000);
  updateCharts();
}

async function start() {

    init();

    await loadPcapData();
    await loadAlerts();

    setInterval(loadPcapData, 3000);
    setInterfal(loadAlerts, 3000);
}

start();
