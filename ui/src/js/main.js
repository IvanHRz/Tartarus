/* TARTARUS UI — Phase 1: Events Dashboard */
'use strict';

const HEALTH_MS = 10000;
const EVENTS_MS = 5000;
const PAGE_SIZE = 50;

let currentOffset = 0;
let currentTotal = 0;
let autoRefreshTimer = null;

// ── DOM refs ──────────────────────────────────
const $ = (id) => document.getElementById(id);
const badge      = $('statusBadge');
const statTotal   = $('statTotal');
const statIPs     = $('statIPs');
const statSSH     = $('statSSH');
const statHTTP    = $('statHTTP');
const statTCP     = $('statTCP');
const eventsBody  = $('eventsBody');
const pageInfo    = $('pageInfo');
const btnPrev     = $('btnPrev');
const btnNext     = $('btnNext');
const filterProto = $('filterProtocol');
const filterIP    = $('filterIP');
const btnRefresh  = $('btnRefresh');
const autoCheck   = $('autoRefresh');
const detailPanel = $('eventDetail');
const detailJSON  = $('detailContent');

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

    // Row click → expand detail
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
btnRefresh.addEventListener('click', () => {
    loadEvents();
    loadStats();
});

btnPrev.addEventListener('click', () => {
    currentOffset = Math.max(0, currentOffset - PAGE_SIZE);
    loadEvents();
});

btnNext.addEventListener('click', () => {
    if (currentOffset + PAGE_SIZE < currentTotal) {
        currentOffset += PAGE_SIZE;
        loadEvents();
    }
});

filterProto.addEventListener('change', () => {
    currentOffset = 0;
    loadEvents();
});

filterIP.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        currentOffset = 0;
        loadEvents();
    }
});

autoCheck.addEventListener('change', () => {
    if (autoCheck.checked) startAutoRefresh();
    else stopAutoRefresh();
});

$('btnCloseDetail').addEventListener('click', () => {
    detailPanel.classList.add('hidden');
});

// ── Init ──────────────────────────────────────
checkHealth();
loadStats();
loadEvents();
setInterval(checkHealth, HEALTH_MS);
startAutoRefresh();
