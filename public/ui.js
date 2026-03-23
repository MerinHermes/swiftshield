/* SwiftShield v2 — UI Logic */
(function () {
  'use strict';

  // ─── Helpers ───────────────────────────────────────────────────────────────
  const $ = (sel, ctx) => (ctx || document).querySelector(sel);

  function showToast(text, type = '') {
    const wrap = $('#toasts');
    if (!wrap) return;
    const el = document.createElement('div');
    el.className = 'toast' + (type ? ' ' + type : '');
    el.textContent = text;
    wrap.appendChild(el);
    setTimeout(() => {
      el.style.opacity = '0';
      el.addEventListener('transitionend', () => el.remove(), { once: true });
    }, 3500);
  }

  async function getCoords() {
    if (!navigator.geolocation) return { lat: null, lon: null };
    try {
      const pos = await new Promise((res, rej) =>
        navigator.geolocation.getCurrentPosition(res, rej, { timeout: 6000 })
      );
      return { lat: pos.coords.latitude, lon: pos.coords.longitude };
    } catch { return { lat: null, lon: null }; }
  }

  async function postJSON(url, payload, extraHeaders = {}) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...extraHeaders },
        body: JSON.stringify(payload)
      });
      return await res.json();
    } catch (e) {
      console.error(e);
      return { error: true };
    }
  }

  // ═══════════════════ USER / LOGIN PAGE ════════════════════════════════════
  if ($('#loginBtn')) {
    const loginBtn   = $('#loginBtn');
    const dot        = $('#statusDot');
    const statusText = $('#statusText');
    const userIdEl   = $('#userId');

    function setStatus(text, state = '') {
      if (statusText) statusText.textContent = text;
      if (dot) { dot.className = 'status-dot' + (state ? ' ' + state : ''); }
    }

    async function gatherAndPost(justification) {
      setStatus('Collecting location data…');
      const { lat, lon } = await getCoords();

      setStatus('Sending to server…');
      const payload = {
        userId:      (userIdEl?.value || 'anonymous').trim(),
        latitude:    lat,
        longitude:   lon,
        deviceInfo:  navigator.userAgent || '',
        justification: justification || null
      };

      const result = await postJSON('/log', payload);

      if (!result || result.error) {
        setStatus('Error — could not reach server', 'danger');
        showToast('Network error', 'danger');
        return;
      }
      if (result.needsJustification) {
        openJustModal();
        setStatus('External access — justification required', 'warn');
        return;
      }
      if (result.logged) {
        const riskState = result.risk === 'high' ? 'danger' : result.risk === 'medium' ? 'warn' : 'active';
        setStatus(`Access logged — risk: ${result.risk || 'low'}`, riskState);
        showToast('Access logged successfully');
      }
    }

    const modal      = $('#justModal');
    const submitJust = $('#submitJust');
    const cancelJust = $('#cancelJust');

    function openJustModal()  { modal?.classList.remove('hidden'); }
    function closeJustModal() { modal?.classList.add('hidden'); }

    loginBtn.addEventListener('click', () => gatherAndPost(null));

    submitJust?.addEventListener('click', async () => {
      const text = ($('#justText')?.value || '').trim();
      if (!text) { showToast('Please enter a justification', 'warn'); return; }
      await gatherAndPost(text);
      closeJustModal();
      if ($('#justText')) $('#justText').value = '';
    });

    cancelJust?.addEventListener('click', () => {
      closeJustModal();
      setStatus('Submission cancelled');
    });
  }

  // ─── File-action logging (upload / download) ───────────────────────────────
  // BUG FIX: logs directly to /log/action — independent of login flow
  async function logFileAction(action, fileName, fileSize, justification) {
    const { lat, lon } = await getCoords();
    return postJSON('/log/action', {
      userId:      ($('#userId')?.value || 'anonymous').trim(),
      action,
      fileName:    fileName  || null,
      fileSize:    fileSize  || null,
      latitude:    lat,
      longitude:   lon,
      deviceInfo:  navigator.userAgent || '',
      justification: justification || null
    });
  }

  const uploadBtn = $('#uploadBtn');
  if (uploadBtn) {
    uploadBtn.addEventListener('click', async () => {
      const file = $('#uploadInput')?.files[0];
      const r = await logFileAction('upload', file?.name, file?.size, null);
      if (r?.needsJustification) {
        const j = prompt('Justification required for external upload:');
        if (j) await logFileAction('upload', file?.name, file?.size, j);
      } else if (r?.logged) showToast('Upload logged');
    });
  }

  const downloadBtn = $('#downloadBtn');
  if (downloadBtn) {
    downloadBtn.addEventListener('click', async () => {
      const fileName = downloadBtn.dataset.file || null;
      const r = await logFileAction('download', fileName, null, null);
      if (r?.needsJustification) {
        const j = prompt('Justification required for external download:');
        if (j) await logFileAction('download', fileName, null, j);
      } else if (r?.logged) showToast('Download logged');
    });
  }

  // ═══════════════════ ADMIN PAGE ═══════════════════════════════════════════
  if (document.querySelector('.logs-card')) {
    const tableBody    = $('#logsTable tbody');
    const emptyState   = $('#emptyState');
    const tableWrap    = $('#tableWrap');
    const statTotal    = $('#statTotal');
    const statHigh     = $('#statHigh');
    const statExternal = $('#statExternal');
    const statUsers    = $('#statUsers');
    const filterUser   = $('#filterUser');
    const filterRisk   = $('#filterRisk');
    const filterAction = $('#filterAction');
    const clearFilters = $('#clearFilters');
    const adminKeyEl   = $('#adminKey');
    const loadBtn      = $('#loadBtn');
    const authBanner   = $('#authBanner');

    let allLogs = [];

    function getAdminKey() { return adminKeyEl?.value?.trim() || ''; }

    function renderRows(rows) {
      tableBody.innerHTML = '';

      if (!rows || rows.length === 0) {
        emptyState?.classList.remove('hidden');
        if (tableWrap) tableWrap.style.display = 'none';
      } else {
        emptyState?.classList.add('hidden');
        if (tableWrap) tableWrap.style.display = 'block';
      }

      const uniqueUsers = new Set();
      let highCount = 0, extCount = 0;

      rows.forEach(r => {
        if (r.risk === 'high') highCount++;
        if (r.outside_office)  extCount++;
        if (r.user_id)         uniqueUsers.add(r.user_id);

        const tr = document.createElement('tr');
        const risk = r.risk || 'low';
        const loc  = (r.latitude && r.longitude)
          ? `${r.latitude.toFixed(4)}, ${r.longitude.toFixed(4)}`
          : '—';

        tr.innerHTML = `
          <td><pre class="mono">${r.id.slice(-8)}</pre></td>
          <td>${escHtml(r.user_id || '—')}</td>
          <td><span class="badge action">${escHtml(r.action || 'login')}</span></td>
          <td><pre class="mono">${escHtml(r.ip || '—')}</pre></td>
          <td><pre class="mono">${escHtml((r.user_agent || '').slice(0, 80))}</pre></td>
          <td><pre class="mono">${loc}</pre></td>
          <td><pre class="mono">${new Date(r.timestamp).toLocaleString()}</pre></td>
          <td><span class="badge ${risk}">${risk.toUpperCase()}</span></td>
          <td><pre class="mono">${escHtml((r.justification || '').slice(0, 100))}</pre></td>
        `;
        tableBody.appendChild(tr);
      });

      if (statTotal)    statTotal.textContent    = rows.length;
      if (statHigh)     statHigh.textContent     = highCount;
      if (statExternal) statExternal.textContent = extCount;
      if (statUsers)    statUsers.textContent    = uniqueUsers.size;
    }

    function escHtml(str) {
      return String(str)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;')
        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    async function loadLogs() {
      const key = getAdminKey();
      if (!key) { showToast('Enter admin key first', 'warn'); return; }
      authBanner?.classList.add('hidden');

      try {
        const res  = await fetch('/api/logs?limit=500', { headers: { 'x-admin-key': key } });
        if (res.status === 401) {
          authBanner?.classList.remove('hidden');
          showToast('Unauthorized — check admin key', 'danger');
          return;
        }
        const data = await res.json();
        allLogs = data.rows || [];
        applyFilters();
        showToast(`Loaded ${allLogs.length} log(s)`);
      } catch (e) {
        showToast('Failed to fetch logs', 'danger');
        console.error(e);
      }
    }

    function applyFilters() {
      let rows = allLogs.slice();
      const u = (filterUser?.value  || '').toLowerCase().trim();
      const r = (filterRisk?.value  || '').trim();
      const a = (filterAction?.value || '').trim();
      if (u) rows = rows.filter(x => (x.user_id || '').toLowerCase().includes(u));
      if (r) rows = rows.filter(x => (x.risk    || '') === r);
      if (a) rows = rows.filter(x => (x.action  || '') === a);
      renderRows(rows);
    }

    loadBtn?.addEventListener('click', loadLogs);
    adminKeyEl?.addEventListener('keydown', e => { if (e.key === 'Enter') loadLogs(); });

    filterUser?.addEventListener('input',  applyFilters);
    filterRisk?.addEventListener('change', applyFilters);
    filterAction?.addEventListener('change', applyFilters);
    clearFilters?.addEventListener('click', () => {
      if (filterUser)   filterUser.value   = '';
      if (filterRisk)   filterRisk.value   = '';
      if (filterAction) filterAction.value = '';
      applyFilters();
    });
  }
})();
