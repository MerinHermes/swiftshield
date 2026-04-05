/* SwiftShield v3 — Admin Dashboard */
(function () {
  'use strict';

  const SESSION_KEY = 'ss_admin_key';
  let adminKey = '';
  let autoRefreshTimer = null;
  let map = null, riskChart = null, hoursChart = null, actionChart = null;
  let allLogs = [], filteredLogs = [];
  let currentPage = 0;
  const PAGE_SIZE = 50;

  // ── Helpers ────────────────────────────────────────────────────────────────
  const $ = id => document.getElementById(id);
  const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

  function showToast(text, type='') {
    const wrap = $('toasts');
    if (!wrap) return;
    const el = document.createElement('div');
    el.className = 'toast' + (type ? ' '+type : '');
    el.textContent = text;
    wrap.appendChild(el);
    setTimeout(() => { el.style.opacity='0'; el.addEventListener('transitionend',()=>el.remove(),{once:true}); }, 3500);
  }

  async function apiFetch(path, opts={}) {
    const res = await fetch(path, { ...opts, headers: { 'x-admin-key': adminKey, 'Content-Type': 'application/json', ...(opts.headers||{}) } });
    return { status: res.status, data: await res.json().catch(()=>({})) };
  }

  // ── Confirm Modal ──────────────────────────────────────────────────────────
  let _confirmResolve = null;
  function showConfirm(title, msg) {
    $('confirmTitle').textContent = title;
    $('confirmMsg').textContent = msg;
    $('confirmModal').classList.remove('hidden');
    return new Promise(res => { _confirmResolve = res; });
  }
  $('confirmOk').addEventListener('click', () => { $('confirmModal').classList.add('hidden'); if(_confirmResolve){_confirmResolve(true);_confirmResolve=null;} });
  $('confirmCancel').addEventListener('click', () => { $('confirmModal').classList.add('hidden'); if(_confirmResolve){_confirmResolve(false);_confirmResolve=null;} });

  // ── Auth ───────────────────────────────────────────────────────────────────
  async function tryUnlock(key) {
    if (!key) return;
    const res = await fetch('/api/admin/verify', { headers: { 'x-admin-key': key } }).catch(()=>({status:0}));
    if (res.status === 200) {
      adminKey = key;
      sessionStorage.setItem(SESSION_KEY, key);
      $('lockScreen').classList.add('hidden');
      $('adminDash').classList.remove('hidden');
      $('lockError').classList.remove('visible');
      initDashboard();
    } else {
      $('lockError').classList.add('visible');
      $('lockKey').value = '';
      $('lockKey').focus();
    }
  }

  function logout() {
    sessionStorage.removeItem(SESSION_KEY);
    adminKey = '';
    clearInterval(autoRefreshTimer);
    $('adminDash').classList.add('hidden');
    $('lockScreen').classList.remove('hidden');
    $('lockKey').value = '';
    $('lockKey').focus();
  }

  $('unlockBtn').addEventListener('click', () => tryUnlock($('lockKey').value.trim()));
  $('lockKey').addEventListener('keydown', e => { if(e.key==='Enter') tryUnlock($('lockKey').value.trim()); });
  $('logoutBtn').addEventListener('click', logout);

  // Restore session after short delay to ensure DOM input elements are ready
  setTimeout(() => {
    const saved = sessionStorage.getItem(SESSION_KEY);
    if (saved) tryUnlock(saved);
  }, 150);

  // ── Tabs ───────────────────────────────────────────────────────────────────
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('active'));
      btn.classList.add('active');
      $('tab-'+btn.dataset.tab).classList.add('active');
      if (btn.dataset.tab==='map') initMap();
      if (btn.dataset.tab==='analytics') loadAnalytics();
    });
  });

  // ── Dashboard Init ─────────────────────────────────────────────────────────
  function initDashboard() {
    $('sessionStart').value = new Date().toLocaleString();
    const lb2 = $('logoutBtn2');
    if (lb2) lb2.addEventListener('click', logout);
    loadConfig();
    loadStats();
    loadLogs();
    loadAllowlist();
    checkDriveStatus();
    startAutoRefresh();
  }

  // ── Config ─────────────────────────────────────────────────────────────────
  async function loadConfig() {
    try {
      const d = await fetch('/config').then(r=>r.json());
      $('cfgLat').value = d.office?.latitude ?? '—';
      $('cfgLon').value = d.office?.longitude ?? '—';
      $('cfgRadius').value = d.office?.radius ?? '—';
    } catch {}
  }

  // ── Stats ──────────────────────────────────────────────────────────────────
  async function loadStats() {
    try {
      const [{data:s},{data:al}] = await Promise.all([apiFetch('/api/stats'),apiFetch('/api/allowlist')]);
      if (s.total!=null) $('statTotal').textContent = s.total;
      if (s.highRisk!=null) $('statHigh').textContent = s.highRisk;
      if (s.externalAccess!=null) $('statExternal').textContent = s.externalAccess;
      if (al.total!=null) $('statAllowlist').textContent = al.total;
    } catch {}
  }

  // ── Logs ───────────────────────────────────────────────────────────────────
  async function loadLogs() {
    try {
      const params = new URLSearchParams({ limit: '1000' });
      const u = ($('filterUser')?.value||'').trim();
      const r = ($('filterRisk')?.value||'');
      const a = ($('filterAction')?.value||'');
      if (r) params.set('risk', r);
      if (a) params.set('action', a);
      if (u) params.set('user_id', u);
      const {status, data} = await apiFetch('/api/logs?'+params);
      if (status===401) { showToast('Session expired','danger'); logout(); return; }
      allLogs = data.rows || [];
      applyFilters();
    } catch { showToast('Failed to load logs','danger'); }
  }

  function applyFilters() {
    const u = ($('filterUser')?.value||'').toLowerCase().trim();
    const r = ($('filterRisk')?.value||'');
    const a = ($('filterAction')?.value||'');
    filteredLogs = allLogs.filter(x => {
      if (u && !(x.user_id||'').toLowerCase().includes(u)) return false;
      if (r && (x.risk||')') !== r) return false;
      if (a && (x.action||'') !== a) return false;
      return true;
    });
    currentPage = 0;
    renderPage();
  }

  function renderPage() {
    const tbody = $('logsBody');
    const tableWrap = $('tableWrap');
    const logsEmpty = $('logsEmpty');
    const pagination = $('logsPagination');
    const countLabel = $('logsCountLabel');
    if (!tbody) return;

    const total = filteredLogs.length;
    if (countLabel) countLabel.textContent = total + ' RECORDS';

    if (!total) {
      logsEmpty.style.display = '';
      tableWrap.style.display = 'none';
      if (pagination) pagination.style.display = 'none';
      return;
    }
    logsEmpty.style.display = 'none';
    tableWrap.style.display = 'block';

    const pageCount = Math.ceil(total/PAGE_SIZE);
    const start = currentPage*PAGE_SIZE;
    const slice = filteredLogs.slice(start, start+PAGE_SIZE);

    tbody.innerHTML = '';
    slice.forEach(r => {
      const risk = r.risk||'low';
      const loc = (r.latitude&&r.longitude) ? Number(r.latitude).toFixed(4)+', '+Number(r.longitude).toFixed(4) : '—';
      const newDeviceBadge = r.new_device ? '<span class="badge new-device" style="margin-left:4px;font-size:.55rem">NEW DEVICE</span>' : '';
      const bulkBadge = r.bulk_download ? '<span class="badge high" style="margin-left:4px;font-size:.55rem">BULK</span>' : '';
      const tr = document.createElement('tr');
      tr.innerHTML =
        '<td><pre class="mono">'+esc(r.id.slice(-8))+'</pre></td>'+
        '<td style="font-weight:600;max-width:180px">'+esc(r.user_id||'—')+newDeviceBadge+'</td>'+
        '<td><span class="badge action">'+esc(r.action||'login')+'</span>'+bulkBadge+'</td>'+
        '<td><pre class="mono">'+esc(r.ip||'—')+'</pre></td>'+
        '<td><pre class="mono" title="'+esc(r.user_agent||'')+'">'+esc((r.device_info||r.user_agent||'—').slice(0,40))+'</pre></td>'+
        '<td><pre class="mono">'+esc(loc)+'</pre></td>'+
        '<td><span class="badge '+esc(risk)+'">'+risk.toUpperCase()+'</span></td>'+
        '<td style="max-width:180px;white-space:normal;word-break:break-word;font-size:.75rem;color:var(--muted)">'+esc((r.justification||'—').slice(0,120))+'</td>'+
        '<td><pre class="mono">'+esc(new Date(r.timestamp).toLocaleString())+'</pre></td>'+
        '<td><button class="btn-icon del-log" data-id="'+esc(r.id)+'" title="Delete">✕</button></td>';
      tbody.appendChild(tr);
    });

    tbody.querySelectorAll('.del-log').forEach(btn => {
      btn.addEventListener('click', async () => {
        const ok = await showConfirm('Delete Log','Remove this log entry permanently?');
        if (!ok) return;
        const {status} = await apiFetch('/api/logs/'+btn.dataset.id, {method:'DELETE'});
        if (status===200) { showToast('Log deleted'); allLogs=allLogs.filter(x=>x.id!==btn.dataset.id); applyFilters(); loadStats(); }
        else showToast('Delete failed','danger');
      });
    });

    if (pageCount>1) {
      pagination.style.display = 'flex';
      $('pageInfo').textContent = 'Page '+(currentPage+1)+' of '+pageCount;
      $('prevPage').disabled = currentPage===0;
      $('nextPage').disabled = currentPage>=pageCount-1;
    } else { pagination.style.display='none'; }
  }

  $('prevPage').addEventListener('click', ()=>{ currentPage--; renderPage(); });
  $('nextPage').addEventListener('click', ()=>{ currentPage++; renderPage(); });
  $('refreshLogs').addEventListener('click', ()=>{ loadLogs(); loadStats(); });
  $('clearFilters').addEventListener('click', ()=>{
    $('filterUser').value=''; $('filterRisk').value=''; $('filterAction').value='';
    applyFilters();
  });
  $('filterUser').addEventListener('input', applyFilters);
  $('filterRisk').addEventListener('change', applyFilters);
  $('filterAction').addEventListener('change', applyFilters);

  // ── Export ─────────────────────────────────────────────────────────────────
  $('exportCsvBtn').addEventListener('click', ()=>{
    if (!filteredLogs.length) { showToast('No logs to export','warn'); return; }
    const cols = ['id','user_id','action','ip','user_agent','latitude','longitude','outside_office','risk','justification','file_name','source','timestamp'];
    const csv = [cols.join(',')].concat(filteredLogs.map(r=>cols.map(k=>JSON.stringify(r[k]??'')).join(','))).join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
    a.download = 'swiftshield-logs-'+new Date().toISOString().slice(0,10)+'.csv';
    a.click();
    showToast('Exported '+filteredLogs.length+' records');
  });

  $('exportDriveBtn').addEventListener('click', async ()=>{
    showToast('Exporting to Google Drive…');
    const {data} = await apiFetch('/api/export-to-drive',{method:'POST'});
    if (data.success) showToast('Exported '+data.rows+' rows → '+data.fileName);
    else showToast('Drive export failed: '+(data.error||'unknown'),'danger');
  });

  // ── Map ────────────────────────────────────────────────────────────────────
  async function initMap() {
    if (!window.L) { showToast('Map library not loaded','warn'); return; }
    if (!map) {
      map = L.map('accessMap',{zoomControl:true}).setView([20.5937,78.9629],5);
      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{
        attribution:'© OpenStreetMap © CARTO', maxZoom:18
      }).addTo(map);
    }
    await loadMapData();
  }

  async function loadMapData() {
    if (!map) return;
    map.eachLayer(l=>{ if(l instanceof L.CircleMarker||l instanceof L.Marker) map.removeLayer(l); });
    const [{data},{data:cfg}] = await Promise.all([apiFetch('/api/analytics'), fetch('/config').then(r=>r.json()).then(d=>({data:d}))]);
    if (cfg.office) {
      L.circleMarker([cfg.office.latitude,cfg.office.longitude],{radius:14,color:'#00dcb4',fillColor:'#00dcb4',fillOpacity:.15,weight:2})
        .addTo(map).bindPopup('<b>Office Perimeter</b><br>Radius: '+cfg.office.radius+'m');
    }
    const colors = {high:'#ff4d6d',medium:'#ffb347',low:'#00dcb4'};
    (data.recentLocations||[]).forEach(loc=>{
      const c = colors[loc.risk]||'#888';
      L.circleMarker([loc.latitude,loc.longitude],{radius:7,color:c,fillColor:c,fillOpacity:.7,weight:1.5})
        .addTo(map).bindPopup('<b>'+esc(loc.user_id||'unknown')+'</b><br>Action: '+(loc.action||'—')+'<br>Risk: <b style="color:'+c+'">'+(loc.risk||'—').toUpperCase()+'</b><br>'+new Date(loc.timestamp).toLocaleString());
    });
    showToast('Map updated with '+((data.recentLocations||[]).length)+' locations');
  }

  $('refreshMap').addEventListener('click', loadMapData);

  // ── Analytics ──────────────────────────────────────────────────────────────
  async function loadAnalytics() {
    const {data} = await apiFetch('/api/analytics');

    // Risk trend
    const days = [...new Set((data.riskTrend||[]).map(d=>d._id.day))].sort();
    const riskColors = {high:'#ff4d6d',medium:'#ffb347',low:'#00dcb4'};
    const datasets = ['high','medium','low'].map(risk=>({
      label:risk.toUpperCase(),
      data:days.map(day=>{ const f=data.riskTrend.find(d=>d._id.day===day&&d._id.risk===risk); return f?f.count:0; }),
      borderColor:riskColors[risk],backgroundColor:riskColors[risk]+'33',tension:.4,fill:true
    }));
    if (riskChart) riskChart.destroy();
    riskChart = new Chart($('riskChart'),{type:'line',data:{labels:days.map(d=>d.slice(5)),datasets},options:{responsive:true,plugins:{legend:{labels:{color:'#8b949e',font:{size:10}}}},scales:{x:{ticks:{color:'#8b949e'},grid:{color:'rgba(255,255,255,.05)'}},y:{ticks:{color:'#8b949e'},grid:{color:'rgba(255,255,255,.05)'}}}}});

    // Hourly
    const hours=Array.from({length:24},(_,i)=>i);
    const hourCounts=hours.map(h=>{const f=(data.hourlyDist||[]).find(d=>d._id===h);return f?f.count:0;});
    if (hoursChart) hoursChart.destroy();
    hoursChart = new Chart($('hoursChart'),{type:'bar',data:{labels:hours.map(h=>h+':00'),datasets:[{label:'Events',data:hourCounts,backgroundColor:'#00dcb433',borderColor:'#00dcb4',borderWidth:1}]},options:{responsive:true,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#8b949e',maxRotation:45},grid:{color:'rgba(255,255,255,.05)'}},y:{ticks:{color:'#8b949e'},grid:{color:'rgba(255,255,255,.05)'}}}}});

    // Action breakdown
    const acts=(data.actionBreakdown||[]);
    if (actionChart) actionChart.destroy();
    actionChart = new Chart($('actionChart'),{type:'doughnut',data:{labels:acts.map(a=>a._id||'unknown'),datasets:[{data:acts.map(a=>a.count),backgroundColor:['#00dcb4','#4db8ff','#ffb347','#ff4d6d','#c084fc'],borderWidth:0}]},options:{responsive:true,plugins:{legend:{position:'bottom',labels:{color:'#8b949e',font:{size:10}}}}}});

    // Top users
    const max=Math.max(...(data.topUsers||[]).map(u=>u.count),1);
    $('topUsersList').innerHTML=(data.topUsers||[]).map(u=>
      '<div class="top-user-row">'+
      '<div class="top-user-name">'+esc(u._id||'unknown')+'</div>'+
      '<div style="flex:2"><div class="top-user-bar" style="width:'+Math.round(u.count/max*100)+'%"></div></div>'+
      '<div class="top-user-count">'+u.count+' events</div>'+
      (u.highRisk?'<span class="badge high">'+u.highRisk+' HIGH</span>':'')+
      '</div>'
    ).join('');
  }

  $('sendReportBtn').addEventListener('click', async ()=>{
    showToast('Sending weekly report…');
    const {data} = await apiFetch('/api/weekly-report',{method:'POST'});
    if (data.success) showToast(data.message);
    else showToast('Report failed: '+(data.error||'unknown'),'danger');
  });

  // ── Allowlist ──────────────────────────────────────────────────────────────
  let allAllowlist = [];

  async function loadAllowlist() {
    try {
      const {status,data} = await apiFetch('/api/allowlist');
      if (status===401) return;
      allAllowlist = data.rows||[];
      renderAllowlist();
    } catch {}
  }

  function renderAllowlist() {
    const tbody=$('allowlistBody'), wrap=$('allowlistTableWrap'), emptyEl=$('allowlistEmpty'), countEl=$('allowlistCount');
    if (!tbody) return;
    const tf=($('filterAllowType')?.value||'');
    const sf=($('filterAllowSearch')?.value||'').toLowerCase();
    const rows=allAllowlist.filter(x=>{ if(tf&&x.type!==tf)return false; if(sf&&!(x.value||'').toLowerCase().includes(sf)&&!(x.note||'').toLowerCase().includes(sf))return false; return true; });
    if (countEl) countEl.textContent=rows.length+' entries';
    if (!rows.length){ emptyEl.style.display=''; wrap.style.display='none'; return; }
    emptyEl.style.display='none'; wrap.style.display='block';
    tbody.innerHTML='';
    rows.forEach(r=>{
      const tr=document.createElement('tr');
      tr.innerHTML='<td><span class="type-badge '+esc(r.type)+'">'+esc(r.type.toUpperCase())+'</span></td>'+
        '<td style="font-family:var(--mono);font-size:.78rem;font-weight:600">'+esc(r.value)+'</td>'+
        '<td style="max-width:240px"><input class="note-input al-note" data-id="'+esc(r.id)+'" value="'+esc(r.note||'')+'" placeholder="Add note…"/></td>'+
        '<td style="font-family:var(--mono);font-size:.7rem;color:var(--muted)">'+esc(new Date(r.createdAt).toLocaleDateString())+'</td>'+
        '<td style="font-family:var(--mono);font-size:.7rem;color:var(--muted)">'+esc(r.addedBy||'admin')+'</td>'+
        '<td><button class="btn-icon del-allow" data-id="'+esc(r.id)+'">✕</button></td>';
      tbody.appendChild(tr);
    });
    tbody.querySelectorAll('.al-note').forEach(inp=>{
      inp.addEventListener('blur',async()=>{ await apiFetch('/api/allowlist/'+inp.dataset.id,{method:'PATCH',body:JSON.stringify({note:inp.value})}); });
      inp.addEventListener('keydown',e=>{ if(e.key==='Enter')inp.blur(); });
    });
    tbody.querySelectorAll('.del-allow').forEach(btn=>{
      btn.addEventListener('click',async()=>{
        const ok=await showConfirm('Remove Entry','Remove this allowlist entry?');
        if (!ok) return;
        const {status}=await apiFetch('/api/allowlist/'+btn.dataset.id,{method:'DELETE'});
        if (status===200){ showToast('Entry removed'); allAllowlist=allAllowlist.filter(x=>x.id!==btn.dataset.id); renderAllowlist(); loadStats(); }
        else showToast('Delete failed','danger');
      });
    });
  }

  $('addAllowBtn').addEventListener('click',async()=>{
    const type=$('newType').value, value=$('newValue').value.trim(), note=$('newNote').value.trim();
    if (!value){ showToast('Enter a value','warn'); return; }
    const {status,data}=await apiFetch('/api/allowlist',{method:'POST',body:JSON.stringify({type,value,note})});
    if (status===200||status===201){ showToast('Entry added'); $('newValue').value=''; $('newNote').value=''; await loadAllowlist(); loadStats(); }
    else if (status===409) showToast('Entry already exists','warn');
    else showToast('Error: '+(data.error||'unknown'),'danger');
  });
  $('newValue').addEventListener('keydown',e=>{ if(e.key==='Enter')$('addAllowBtn').click(); });
  $('filterAllowType').addEventListener('change',renderAllowlist);
  $('filterAllowSearch').addEventListener('input',renderAllowlist);

  // ── Settings ───────────────────────────────────────────────────────────────
  $('clearHighRisk').addEventListener('click',async()=>{
    const ok=await showConfirm('Clear HIGH RISK Logs','Delete ALL high-risk log entries permanently?');
    if (!ok) return;
    const {data}=await apiFetch('/api/logs?risk=high',{method:'DELETE'});
    showToast('Deleted '+(data.deleted||0)+' high-risk logs'); loadLogs(); loadStats();
  });
  $('clearAllLogs').addEventListener('click',async()=>{
    const ok=await showConfirm('Clear ALL Logs','This will permanently delete every log. Cannot be undone.');
    if (!ok) return;
    const ok2=await showConfirm('Final Confirmation','Second confirmation: delete ALL logs?');
    if (!ok2) return;
    const {data}=await apiFetch('/api/logs',{method:'DELETE'});
    showToast('Deleted '+(data.deleted||0)+' logs'); loadLogs(); loadStats();
  });

  // ── Drive ──────────────────────────────────────────────────────────────────
  async function checkDriveStatus() {
    const {data}=await apiFetch('/api/drive/status');
    $('driveStatus').textContent = data.connected ? '✅ Google Drive connected' : '⚠ Not connected';
    $('driveStatus').style.color = data.connected ? 'var(--accent)' : 'var(--warn)';
  }

  $('renewWatchBtn').addEventListener('click',async()=>{
    showToast('Renewing Drive webhook…');
    const {data}=await apiFetch('/api/drive/watch',{method:'POST'});
    if (data.success) showToast('Webhook renewed until '+new Date(data.expiration).toLocaleDateString());
    else showToast('Renew failed: '+(data.error||'unknown'),'danger');
  });

  $('pollNowBtn').addEventListener('click',async()=>{
    showToast('Polling Drive reports…');
    const {data}=await apiFetch('/api/drive/poll',{method:'POST'});
    if (data.success){ showToast(data.message); loadLogs(); loadStats(); }
    else showToast('Poll failed: '+(data.error||'unknown'),'danger');
  });

  // ── Auto-refresh ───────────────────────────────────────────────────────────
  function startAutoRefresh() {
    clearInterval(autoRefreshTimer);
    const interval = parseInt($('autoRefreshSelect').value)*1000;
    if (interval>0) autoRefreshTimer = setInterval(()=>{ loadLogs(); loadStats(); }, interval);
  }
  $('autoRefreshSelect').addEventListener('change', startAutoRefresh);

})();
