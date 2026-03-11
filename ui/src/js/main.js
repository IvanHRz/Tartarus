/* TARTARUS UI — Phase 2: Events + Scanner Dashboard */
'use strict';

const HEALTH_MS = 10000;
const EVENTS_MS = 5000;
const PAGE_SIZE = 50;

let currentOffset = 0;
let currentTotal = 0;
let autoRefreshTimer = null;

// ── DOM refs ──────────────────────────────────
const $ = (id) => document.getElementById(id);
const badge       = $('statusBadge');
const scanBadge   = $('scanBadge');
const statTotal   = $('statTotal');
const statIPs     = $('statIPs');
const statSSH     = $('statSSH');
const statHTTP    = $('statHTTP');
const statTCP     = $('statTCP');
const eventsBody  = $('eventsBody');
const hostsBody   = $('hostsBody');
const hostsCount  = $('hostsCount');
const pageInfo    = $('pageInfo');
const btnPrev     = $('btnPrev');
const btnNext     = $('btnNext');
const filterProto = $('filterProtocol');
const filterIP    = $('filterIP');
const btnRefresh  = $('btnRefresh');
const autoCheck   = $('autoRefresh');
const detailPanel = $('eventDetail');
const detailJSON  = $('detailContent');
const scanTarget  = $('scanTarget');
const scanProfile = $('scanProfile');
const btnScan     = $('btnScan');
const scanStatus  = $('scanStatus');

// ── Health Check ──────────────────────────────
async function checkHealth() {
    try {
        const res = await fetch('/api/health');
        const data = await res.json();
        if (data.status === 'ok') {
            badge.textContent = 'Connected';
            badge.className = 'badge badge-green';
        } else {
            badge.textContent = 'Degraded';
            badge.className = 'badge badge-yellow';
        }
    } catch (_) {
        badge.textContent = 'Offline';
        badge.className = 'badge badge-red';
    }
}

// ── Stats ─────────────────────────────────────
async function loadStats() {
    try {
        const res = await fetch('/api/events/stats');
        const data = await res.json();
        statTotal.textContent = data.total_events.toLocaleString();
        statIPs.textContent = data.unique_source_ips.toLocaleString();
        statSSH.textContent = (data.by_protocol.SSH || 0).toLocaleString();
        statHTTP.textContent = (data.by_protocol.HTTP || 0).toLocaleString();
        statTCP.textContent = (data.by_protocol.TCP || 0).toLocaleString();
    } catch (_) {
        statTotal.textContent = '—';
    }
}

// ── Events Table ──────────────────────────────
async function loadEvents() {
    const proto = filterProto.value;
    const ip = filterIP.value.trim();

    let url = `/api/events?limit=${PAGE_SIZE}&offset=${currentOffset}`;
    if (proto) url += `&protocol=${proto}`;
    if (ip) url += `&source_ip=${encodeURIComponent(ip)}`;

    try {
        const res = await fetch(url);
        const data = await res.json();
        currentTotal = data.total;
        renderTable(data.events);
        updatePagination();
    } catch (_) {
        eventsBody.innerHTML = '<tr><td colspan="6" class="table-empty">Failed to load events</td></tr>';
    }
}

function renderTable(events) {
    if (!events.length) {
        eventsBody.innerHTML = '<tr><td colspan="6" class="table-empty">No events found</td></tr>';
        return;
    }

    eventsBody.innerHTML = events.map(ev => {
        const ts = new Date(ev.timestamp).toLocaleString('es-MX', {
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
            hour12: false
        });
        const sha = ev.sha256 ? ev.sha256.substring(0, 10) + '...' : '—';
        const cmd = escapeHtml(ev.command || '—');
        const protoBadge = `<span class="proto-badge proto-${ev.protocol.toLowerCase()}">${ev.protocol}</span>`;

        return `<tr class="event-row" data-payload='${escapeAttr(JSON.stringify(ev.payload))}'>
            <td class="col-ts">${ts}</td>
            <td class="col-ip">${ev.source_ip}</td>
            <td class="col-port">${ev.dest_port || '—'}</td>
            <td>${protoBadge}</td>
            <td class="col-cmd" title="${escapeAttr(ev.command || '')}">${cmd}</td>
            <td class="col-hash">${sha}</td>
        </tr>`;
    }).join('');

    eventsBody.querySelectorAll('.event-row').forEach(row => {
        row.addEventListener('click', () => {
            try {
                const payload = JSON.parse(row.dataset.payload);
                const formatted = JSON.stringify(
                    typeof payload === 'string' ? JSON.parse(payload) : payload,
                    null, 2
                );
                detailJSON.textContent = formatted;
            } catch (_) {
                detailJSON.textContent = row.dataset.payload;
            }
            detailPanel.classList.remove('hidden');
        });
    });
}

function updatePagination() {
    const totalPages = Math.max(1, Math.ceil(currentTotal / PAGE_SIZE));
    const currentPage = Math.floor(currentOffset / PAGE_SIZE) + 1;
    pageInfo.textContent = `Page ${currentPage} of ${totalPages} (${currentTotal} events)`;
    btnPrev.disabled = currentOffset === 0;
    btnNext.disabled = currentOffset + PAGE_SIZE >= currentTotal;
}

// ── Network Scanner ──────────────────────────
async function startScan() {
    const target = scanTarget.value.trim();
    if (!target) {
        scanStatus.textContent = 'Enter a target CIDR';
        scanStatus.className = 'scan-status scan-error';
        return;
    }

    btnScan.disabled = true;
    btnScan.textContent = 'Scanning...';
    scanStatus.textContent = `Queuing scan for ${target}...`;
    scanStatus.className = 'scan-status scan-active';

    try {
        const res = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, profile: scanProfile.value }),
        });
        const data = await res.json();
        if (data.status === 'queued') {
            scanStatus.textContent = `Scan queued (${data.profile}) — Job: ${data.job_id}`;
            scanBadge.textContent = 'Scanning...';
            scanBadge.className = 'badge badge-yellow';
            pollScanStatus();
        } else {
            scanStatus.textContent = `Error: ${data.error || 'Unknown'}`;
            scanStatus.className = 'scan-status scan-error';
        }
    } catch (e) {
        scanStatus.textContent = `Failed: ${e.message}`;
        scanStatus.className = 'scan-status scan-error';
    } finally {
        btnScan.disabled = false;
        btnScan.textContent = 'Scan Network';
    }
}

async function pollScanStatus() {
    const poll = async () => {
        try {
            const res = await fetch('/api/scan/status');
            const data = await res.json();

            if (data.status === 'scanning') {
                scanBadge.textContent = `Scanning: ${data.target || '...'}`;
                scanBadge.className = 'badge badge-yellow';
                setTimeout(poll, 3000);
            } else {
                scanBadge.textContent = 'Scanner: Idle';
                scanBadge.className = 'badge badge-muted';
                if (data.last_result) {
                    scanStatus.textContent = `Last scan: ${data.last_result.hosts_found} hosts found`;
                    scanStatus.className = 'scan-status scan-done';
                }
                loadHosts();
            }
        } catch (_) {
            scanBadge.textContent = 'Scanner: Error';
            scanBadge.className = 'badge badge-red';
        }
    };
    setTimeout(poll, 2000);
}

// ── Hosts Table ──────────────────────────────
async function loadHosts() {
    try {
        const res = await fetch('/api/hosts?limit=100');
        const data = await res.json();
        hostsCount.textContent = `${data.total} hosts`;

        if (!data.hosts.length) {
            hostsBody.innerHTML = '<tr><td colspan="6" class="table-empty">No hosts discovered yet. Run a scan to discover network hosts.</td></tr>';
            return;
        }

        hostsBody.innerHTML = data.hosts.map(h => {
            const ports = h.open_ports ? JSON.parse(h.open_ports).map(p =>
                `<span class="port-badge">${p.port}/${p.protocol}</span>`
            ).join(' ') : '—';
            const lastSeen = new Date(h.last_seen).toLocaleString('es-MX', {
                month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false
            });

            return `<tr>
                <td class="col-ip">${h.ip}</td>
                <td>${h.hostname || '—'}</td>
                <td class="col-os">${h.os_fingerprint || '—'}</td>
                <td class="col-ports">${ports}</td>
                <td class="col-mac">${h.mac_address || '—'}</td>
                <td class="col-ts">${lastSeen}</td>
            </tr>`;
        }).join('');
    } catch (_) {
        hostsBody.innerHTML = '<tr><td colspan="6" class="table-empty">Failed to load hosts</td></tr>';
    }
}

// ── Helpers ───────────────────────────────────
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function escapeAttr(str) {
    return str.replace(/&/g, '&amp;').replace(/'/g, '&#39;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ── Auto-refresh ──────────────────────────────
function startAutoRefresh() {
    stopAutoRefresh();
    autoRefreshTimer = setInterval(() => {
        loadEvents();
        loadStats();
    }, EVENTS_MS);
}

function stopAutoRefresh() {
    if (autoRefreshTimer) {
        clearInterval(autoRefreshTimer);
        autoRefreshTimer = null;
    }
}

// ── Event Listeners ───────────────────────────
btnRefresh.addEventListener('click', () => { loadEvents(); loadStats(); });
btnPrev.addEventListener('click', () => { currentOffset = Math.max(0, currentOffset - PAGE_SIZE); loadEvents(); });
btnNext.addEventListener('click', () => { if (currentOffset + PAGE_SIZE < currentTotal) { currentOffset += PAGE_SIZE; loadEvents(); } });
filterProto.addEventListener('change', () => { currentOffset = 0; loadEvents(); });
filterIP.addEventListener('keydown', (e) => { if (e.key === 'Enter') { currentOffset = 0; loadEvents(); } });
autoCheck.addEventListener('change', () => { if (autoCheck.checked) startAutoRefresh(); else stopAutoRefresh(); });
$('btnCloseDetail').addEventListener('click', () => { detailPanel.classList.add('hidden'); });
btnScan.addEventListener('click', startScan);

// ── Init ──────────────────────────────────────
checkHealth();
loadStats();
loadEvents();
loadHosts();
setInterval(checkHealth, HEALTH_MS);
startAutoRefresh();
// Check scan status on load
pollScanStatus();
