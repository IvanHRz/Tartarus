/* TARTARUS UI — Phase 0: Health Dashboard */
'use strict';

const POLL_MS = 5000;

async function checkHealth() {
    const el = document.getElementById('healthChecks');
    const badge = document.getElementById('statusBadge');

    try {
        const res = await fetch('/api/health');
        const data = await res.json();

        let html = '';
        for (const [svc, status] of Object.entries(data.checks || {})) {
            const ok = status === 'ok';
            html += `<div class="check-row">
                <span class="check-name">${svc}</span>
                <span class="check-status ${ok ? 'check-ok' : 'check-fail'}">${ok ? '\u25cf' : '\u2716'} ${status}</span>
            </div>`;
        }
        el.innerHTML = html || '<div class="check-row"><span class="check-name">No checks returned</span></div>';

        if (data.status === 'ok') {
            badge.textContent = 'All Systems OK';
            badge.className = 'badge badge-green';
        } else {
            badge.textContent = 'Degraded';
            badge.className = 'badge badge-yellow';
        }
    } catch (_) {
        el.innerHTML = '<div class="check-row"><span class="check-name">Engine</span><span class="check-status check-fail">\u2716 Unreachable</span></div>';
        badge.textContent = 'Offline';
        badge.className = 'badge badge-red';
    }
}

checkHealth();
setInterval(checkHealth, POLL_MS);
