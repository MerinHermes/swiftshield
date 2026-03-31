/* SwiftShield v2 — Admin Dashboard Logic */
(function () {
  'use strict';

  // ── Helpers ────────────────────────────────────────────────────────────────
  const $ = (sel, ctx) => (ctx || document).querySelector(sel);
  const SESSION_KEY = 'ss_admin_key';
  let adminKey = '';

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

  function escHtml(str) {
    return String(str || '')
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  async function apiFetch(path, opts = {}) {
    const res = await fetch(path, {
      ...opts,
      headers: { 'x-admin-key': adminKey, 'Content-Type': 'application/json', ...(opts.headers || {}) }
    });
    return { status: res.status, data: await res.json().catch(() => ({})) };
  }

  // ── Lock screen ────────────────────────────────────────────────────────────
  const lockScreen = $('#lockScreen');
  const adminDash  = $('#adminDash');
  const lockKeyEl  = $('#lockKey');
  const lockError  = $('#lockError');
  const unlockBtn  = $('#unlockBtn');

  async function tryUnlock(key) {
    if (!key) return;
    const { status } = await fetch('/api/admin/verify', {
      headers: { 'x-admin-key': key }
    }).then(r => ({ status: r.status })).catch(() => ({ status: 0 }));

    if (status === 200) {
      adminKey = key;
      sessionStorage.setItem(SESSION_KEY, key);
      lockScreen.classList.add('hidden');
      adminDash.classList.remove('hidden');
      lockError.classList.remove('visible');
      initDashboard();
    } else {
      lockError.classList.add('visible');
      lockKeyEl.value = '';
      lockKeyEl.focus();
    }
  }

  unlockBtn.addEventListener('click', () => tryUnlock(lockKeyEl.value.trim()));
  lockKeyEl.addEventListener('keydown', e => { if (e.key === 'Enter') tryUnlock(lockKeyEl.value.trim()); });

  // Check session storage on load
  const savedKey = sessionStorage.getItem(SESSION_KEY);
  if (savedKey) tryUnlock(savedKey);

  // ── Logout ──────────────────────────────────────────────────────────────────
  function logout() {
    sessionStorage.removeItem(SESSION_KEY);
    adminKey = '';
    adminDash.classList.add('hidden');
    lockScreen.classList.remove('hidden');
    lockKeyEl.value = '';
    lockKeyEl.focus();
  }
  $('#logoutBtn').addEventListener('click', logout);

  // ── Tabs ────────────────────────────────────────────────────────────────────
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      $('#tab-' + btn.dataset.tab).classList.add('active');
    });
  });

  // ── Confirm Modal ───────────────────────────────────────────────────────────
  let _confirmResolve = null;
  function confirm(title, msg) {
    $('#confirmTitle').textContent = title;
    $('#confirmMsg').textContent   = msg;
    $('#confirmModal').classList.remove('hidden');
    return new Promise(res => { _confirmResolve = res; });
  }
  $('#confirmOk').addEventListener('click', () => {
    $('#confirmModal').classList.add('hidden');
    if (_confirmResolve) { _confirmResolve(true); _confirmResolve = null; }
  });
  $('#confirmCancel').addEventListener('click', () => {
    $('#confirmModal').classList.add('hidden');
    if (_confirmResolve) { _confirmResolve(false); _confirmResolve = null; }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // DASHBOARD INIT
  // ══════════════════════════════════════════════════════════════════════════
  function initDashboard() {
    $('#sessionStart').value = new Date().toLocaleString();
    loadConfig();
    loadStats();
    loadLogs();
    loadAllowlist();

    // Second logout button (settings tab)
    const lb2 = $('#logoutBtn2');
    if (lb2) lb2.addEventListener('click', logout);
  }

  // ── Config ──────────────────────────────────────────────────────────────────
  async function loadConfig() {
    try {
      const res  = await fetch('/config');
      const data = await res.json();
      $('#cfgLat').value    = data.office?.latitude  ?? '—';
      $('#cfgLon').value    = data.office?.longitude ?? '—';
      $('#cfgRadius').value = data.office?.radius    ?? '—';
    } catch {}
  }

  // ── Stats ───────────────────────────────────────────────────────────────────
  async function loadStats() {
    try {
      const { data: s }  = await apiFetch('/api/stats');
      const { data: al } = await apiFetch('/api/allowlist');
      if (s.total      != null) $('#statTotal').textContent    = s.total;
      if (s.highRisk   != null) $('#statHigh').textContent     = s.highRisk;
      if (s.externalAccess != null) $('#statExternal').textContent = s.externalAccess;
      if (al.total     != null) $('#statAllowlist').textContent = al.total;
    } catch {}
  }

  // ══════════════════════════════════════════════════════════════════════════
  // LOGS TAB
  // ══════════════════════════════════════════════════════════════════════════
  let allLogs    = [];
  let filteredLogs = [];
  const PAGE_SIZE  = 50;
  let currentPage  = 0;

  async function loadLogs() {
    try {
      const params = new URLSearchParams({ limit: '1000' });
      const u = ($('#filterUser')?.value  || '').trim();
      const r = ($('#filterRisk')?.value  || '').trim();
      const a = ($('#filterAction')?.value || '').trim();
      if (r) params.set('risk', r);
      if (a) params.set('action', a);
      if (u) params.set('user_id', u);

      const { status, data } = await apiFetch('/api/logs?' + params);
      if (status === 401) { showToast('Session expired — please re-authenticate', 'danger'); logout(); return; }
      allLogs = data.rows || [];
      applyFilters();
    } catch (e) {
      showToast('Failed to load logs', 'danger');
    }
  }

  function applyFilters() {
    const u = ($('#filterUser')?.value   || '').toLowerCase().trim();
    const r = ($('#filterRisk')?.value   || '').trim();
    const a = ($('#filterAction')?.value || '').trim();
    filteredLogs = allLogs.filter(x => {
      if (u && !(x.user_id || '').toLowerCase().includes(u)) return false;
      if (r && (x.risk   || '') !== r) return false;
      if (a && (x.action || '') !== a) return false;
      return true;
    });
    currentPage = 0;
    renderPage();
  }

  function renderPage() {
    const logsBody     = $('#logsBody');
    const tableWrap    = $('#tableWrap');
    const logsEmpty    = $('#logsEmpty');
    const pagination   = $('#logsPagination');
    const countLabel   = $('#logsCountLabel');
    if (!logsBody) return;

    const total = filteredLogs.length;
    if (countLabel) countLabel.textContent = total + ' RECORD' + (total !== 1 ? 'S' : '');

    if (total === 0) {
      logsEmpty.classList.remove('hidden');
      tableWrap.style.display = 'none';
      if (pagination) pagination.style.display = 'none';
      return;
    }

    logsEmpty.classList.add('hidden');
    tableWrap.style.display = 'block';

    const pageCount = Math.ceil(total / PAGE_SIZE);
    const start     = currentPage * PAGE_SIZE;
    const slice     = filteredLogs.slice(start, start + PAGE_SIZE);

    logsBody.innerHTML = '';
    slice.forEach(r => {
      const risk = r.risk || 'low';
      const loc  = (r.latitude && r.longitude)
        ? `${Number(r.latitude).toFixed(4)}, ${Number(r.longitude).toFixed(4)}`
        : '—';
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><pre class="mono">${escHtml(r.id.slice(-8))}</pre></td>
        <td style="font-weight:600">${escHtml(r.user_id || '—')}</td>
        <td><span class="badge action">${escHtml(r.action || 'login')}</span></td>
        <td><pre class="mono">${escHtml(r.ip || '—')}</pre></td>
        <td><pre class="mono" title="${escHtml(r.user_agent||'')}">${escHtml((r.user_agent || '').slice(0, 60))}${(r.user_agent||'').length > 60 ? '…' : ''}</pre></td>
        <td><pre class="mono">${escHtml(loc)}</pre></td>
        <td><span class="badge ${escHtml(risk)}">${risk.toUpperCase()}</span></td>
        <td style="max-width:180px;white-space:normal;word-break:break-word;font-size:.75rem;color:var(--muted)">${escHtml((r.justification || '—').slice(0, 120))}</td>
        <td><pre class="mono">${escHtml(new Date(r.timestamp).toLocaleString())}</pre></td>
        <td><button class="btn-icon del-log" data-id="${escHtml(r.id)}" title="Delete log">✕</button></td>
      `;
      logsBody.appendChild(tr);
    });

    // Pagination
    if (pageCount > 1) {
      if (pagination) {
        pagination.style.display = 'flex';
        $('#pageInfo').textContent = `Page ${currentPage + 1} of ${pageCount}`;
        $('#prevPage').disabled = currentPage === 0;
        $('#nextPage').disabled = currentPage >= pageCount - 1;
      }
    } else {
      if (pagination) pagination.style.display = 'none';
    }

    // Delete single log
    logsBody.querySelectorAll('.del-log').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        const ok = await confirm('Delete Log', `Delete log entry ${id.slice(-8)}? This cannot be undone.`);
        if (!ok) return;
        const { status } = await apiFetch('/api/logs/' + id, { method: 'DELETE' });
        if (status === 200) {
          showToast('Log deleted');
          allLogs = allLogs.filter(x => x.id !== id);
          applyFilters();
          loadStats();
        } else {
          showToast('Delete failed', 'danger');
        }
      });
    });
  }

  // Pagination buttons
  $('#prevPage')?.addEventListener('click', () => { currentPage--; renderPage(); });
  $('#nextPage')?.addEventListener('click', () => { currentPage++; renderPage(); });

  // Filter listeners
  $('#filterUser')?.addEventListener('input',   applyFilters);
  $('#filterRisk')?.addEventListener('change',  applyFilters);
  $('#filterAction')?.addEventListener('change', applyFilters);
  $('#clearFilters')?.addEventListener('click', () => {
    $('#filterUser').value   = '';
    $('#filterRisk').value   = '';
    $('#filterAction').value = '';
    applyFilters();
  });
  $('#refreshLogs')?.addEventListener('click', loadLogs);

  // Export CSV
  $('#exportCsvBtn')?.addEventListener('click', () => {
    if (!filteredLogs.length) { showToast('No logs to export', 'warn'); return; }
    const cols = ['id','user_id','action','ip','user_agent','latitude','longitude','outside_office','risk','justification','timestamp'];
    const csv  = [cols.join(',')].concat(filteredLogs.map(r =>
      cols.map(k => JSON.stringify(r[k] ?? '')).join(',')
    )).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = 'swiftshield-logs.csv'; a.click();
    URL.revokeObjectURL(url);
    showToast('Exported ' + filteredLogs.length + ' records');
  });

  // ══════════════════════════════════════════════════════════════════════════
  // ALLOWLIST TAB
  // ══════════════════════════════════════════════════════════════════════════
  let allAllowlist = [];

  async function loadAllowlist() {
    try {
      const { status, data } = await apiFetch('/api/allowlist');
      if (status === 401) return;
      allAllowlist = data.rows || [];
      renderAllowlist();
    } catch {}
  }

  function renderAllowlist() {
    const tbody        = $('#allowlistBody');
    const wrap         = $('#allowlistTableWrap');
    const emptyEl      = $('#allowlistEmpty');
    const countEl      = $('#allowlistCount');
    if (!tbody) return;

    const typeFilter   = ($('#filterAllowType')?.value   || '').trim();
    const searchFilter = ($('#filterAllowSearch')?.value || '').toLowerCase().trim();

    const rows = allAllowlist.filter(x => {
      if (typeFilter   && x.type !== typeFilter) return false;
      if (searchFilter && !(
        (x.value||'').toLowerCase().includes(searchFilter) ||
        (x.note||'').toLowerCase().includes(searchFilter)
      )) return false;
      return true;
    });

    if (countEl) countEl.textContent = rows.length + ' entr' + (rows.length !== 1 ? 'ies' : 'y');

    if (!rows.length) {
      emptyEl.classList.remove('hidden');
      wrap.style.display = 'none';
      return;
    }
    emptyEl.classList.add('hidden');
    wrap.style.display = 'block';

    tbody.innerHTML = '';
    rows.forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="type-badge ${escHtml(r.type)}">${escHtml(r.type.toUpperCase())}</span></td>
        <td style="font-family:var(--mono);font-size:.78rem;font-weight:600">${escHtml(r.value)}</td>
        <td style="max-width:240px">
          <input class="note-input al-note" data-id="${escHtml(r.id)}" value="${escHtml(r.note||'')}" placeholder="Add note…" title="Click to edit"/>
        </td>
        <td style="font-family:var(--mono);font-size:.7rem;color:var(--muted)">${escHtml(new Date(r.createdAt).toLocaleDateString())}</td>
        <td style="font-family:var(--mono);font-size:.7rem;color:var(--muted)">${escHtml(r.addedBy||'admin')}</td>
        <td><button class="btn-icon del-allow" data-id="${escHtml(r.id)}" title="Remove from allowlist">✕</button></td>
      `;
      tbody.appendChild(tr);
    });

    // Inline note editing — save on blur
    tbody.querySelectorAll('.al-note').forEach(inp => {
      inp.addEventListener('blur', async () => {
        const id   = inp.dataset.id;
        const note = inp.value.trim();
        await apiFetch('/api/allowlist/' + id, {
          method: 'PATCH',
          body: JSON.stringify({ note })
        });
        // Update local copy
        const entry = allAllowlist.find(x => x.id === id);
        if (entry) entry.note = note;
      });
      inp.addEventListener('keydown', e => { if (e.key === 'Enter') inp.blur(); });
    });

    // Delete entry
    tbody.querySelectorAll('.del-allow').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id  = btn.dataset.id;
        const row = allAllowlist.find(x => x.id === id);
        const ok  = await confirm('Remove Entry', `Remove "${row?.value}" from allowlist?`);
        if (!ok) return;
        const { status } = await apiFetch('/api/allowlist/' + id, { method: 'DELETE' });
        if (status === 200) {
          showToast('Entry removed');
          allAllowlist = allAllowlist.filter(x => x.id !== id);
          renderAllowlist();
          loadStats();
        } else {
          showToast('Delete failed', 'danger');
        }
      });
    });
  }

  // Add entry
  $('#addAllowBtn')?.addEventListener('click', async () => {
    const type  = $('#newType')?.value?.trim()  || '';
    const value = $('#newValue')?.value?.trim() || '';
    const note  = $('#newNote')?.value?.trim()  || '';
    if (!value) { showToast('Enter a value first', 'warn'); return; }

    const { status, data } = await apiFetch('/api/allowlist', {
      method: 'POST',
      body: JSON.stringify({ type, value, note })
    });
    if (status === 200 || status === 201) {
      showToast(`Added ${type}: ${value}`);
      $('#newValue').value = '';
      $('#newNote').value  = '';
      await loadAllowlist();
      loadStats();
    } else if (status === 409) {
      showToast('Entry already exists', 'warn');
    } else if (data.error === 'invalid_email') {
      showToast('Invalid email address', 'warn');
    } else if (data.error === 'invalid_ip') {
      showToast('Invalid IP address', 'warn');
    } else {
      showToast('Failed to add entry', 'danger');
    }
  });

  $('#newValue')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') $('#addAllowBtn')?.click();
  });

  // Allowlist filters
  $('#filterAllowType')?.addEventListener('change',  renderAllowlist);
  $('#filterAllowSearch')?.addEventListener('input', renderAllowlist);

  // ══════════════════════════════════════════════════════════════════════════
  // SETTINGS — Danger Zone
  // ══════════════════════════════════════════════════════════════════════════
  $('#clearHighRisk')?.addEventListener('click', async () => {
    const ok = await confirm('Clear High Risk Logs', 'Delete ALL high-risk log entries permanently?');
    if (!ok) return;
    const { status, data } = await apiFetch('/api/logs?risk=high', { method: 'DELETE' });
    if (status === 200) {
      showToast(`Deleted ${data.deleted} high-risk log(s)`);
      loadLogs(); loadStats();
    } else {
      showToast('Operation failed', 'danger');
    }
  });

  $('#clearAllLogs')?.addEventListener('click', async () => {
    const ok = await confirm('Clear ALL Logs', 'This will permanently delete every access log. Are you absolutely sure?');
    if (!ok) return;
    const ok2 = await confirm('Final Confirmation', 'Second confirmation: delete ALL logs? This cannot be undone.');
    if (!ok2) return;
    const { status, data } = await apiFetch('/api/logs', { method: 'DELETE' });
    if (status === 200) {
      showToast(`Deleted ${data.deleted} log(s)`);
      loadLogs(); loadStats();
    } else {
      showToast('Operation failed', 'danger');
    }
  });

})();
