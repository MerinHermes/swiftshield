(function() {
  'use strict';

  let coords      = { lat: null, lon: null };
  let officeConf  = null;
  let isOutside   = null;

  const pd = [1,2,3].map(i => document.getElementById('pd'+i));
  const stepLabel = document.getElementById('stepLabel');
  const steps = ['STEP 1 OF 3 — IDENTIFY YOURSELF','STEP 2 OF 3 — CONFIRM DETAILS','STEP 3 OF 3 — LOGGING ACCESS'];

  function setStep(n) {
    pd.forEach((d,i) => {
      d.className = 'prog-dot' + (i===n-1?' active': i<n-1?' done':'');
    });
    stepLabel.textContent = steps[n-1]||'';
  }

  function show(id)  { document.getElementById(id).style.display='block'; }
  function hide(id)  { document.getElementById(id).style.display='none'; }

  function toast(msg, type='') {
    const w = document.getElementById('toasts');
    const el = document.createElement('div');
    el.className = 'toast' + (type?' '+type:'');
    el.textContent = msg;
    w.appendChild(el);
    setTimeout(() => { el.style.opacity='0'; el.addEventListener('transitionend',()=>el.remove()); }, 3500);
  }

  // Load office config
  fetch('/config').then(r=>r.json()).then(d=>{ officeConf=d.office; }).catch(()=>{});

  function haversine(lat1,lon1,lat2,lon2) {
    const r=x=>x*Math.PI/180, R=6371e3;
    const a=Math.sin(r(lat2-lat1)/2)**2+Math.cos(r(lat1))*Math.cos(r(lat2))*Math.sin(r(lon2-lon1)/2)**2;
    return R*2*Math.atan2(Math.sqrt(a),Math.sqrt(1-a));
  }

  function getLocation() {
    return new Promise(resolve => {
      if (!navigator.geolocation) return resolve({lat:null,lon:null});
      navigator.geolocation.getCurrentPosition(
        p => resolve({lat:p.coords.latitude, lon:p.coords.longitude}),
        () => resolve({lat:null,lon:null}),
        { timeout:8000 }
      );
    });
  }

  function updateLocPill() {
    const pill = document.getElementById('locPill');
    const text = document.getElementById('locText');
    const justWrap = document.getElementById('justWrap');
    const btn  = document.getElementById('s2Submit');
    const action = document.getElementById('actionType').value;
    const label = action==='login' ? 'LOG ACCESS & CONTINUE'
                : action==='download' ? 'LOG DOWNLOAD & CONTINUE'
                : 'LOG UPLOAD & CONTINUE';

    if (coords.lat === null) {
      pill.className = 'loc-pill outside';
      text.textContent = 'Location unavailable — justification required';
      isOutside = true;
      justWrap.style.display = 'block';
    } else if (officeConf) {
      const dist = haversine(coords.lat,coords.lon,officeConf.latitude,officeConf.longitude);
      isOutside = dist > officeConf.radius;
      if (isOutside) {
        pill.className = 'loc-pill outside';
        text.textContent = `Outside office — ${(dist/1000).toFixed(1)} km away`;
        justWrap.style.display = 'block';
      } else {
        pill.className = 'loc-pill inside';
        text.textContent = `Inside office — ${Math.round(dist)} m from centre`;
        justWrap.style.display = 'none';
      }
    } else {
      pill.className = 'loc-pill';
      text.textContent = `Location: ${coords.lat.toFixed(4)}, ${coords.lon.toFixed(4)}`;
      isOutside = true;
      justWrap.style.display = 'block';
    }

    btn.disabled = false;
    btn.textContent = label;
  }

  // ── Step 1 Next ──────────────────────────────────────────────────────────
  document.getElementById('s1Next').addEventListener('click', async () => {
    const userId = document.getElementById('userId').value.trim();
    if (!userId) {
      document.getElementById('userId').classList.add('err');
      document.getElementById('errUserId').classList.add('show');
      document.getElementById('userId').focus();
      return;
    }
    document.getElementById('userId').classList.remove('err');
    document.getElementById('errUserId').classList.remove('show');

    hide('s1'); show('s2'); setStep(2);

    const btn = document.getElementById('s2Submit');
    btn.disabled = true;
    btn.textContent = 'DETECTING LOCATION…';

    coords = await getLocation();
    updateLocPill();
  });

  // ── Step 2 Back ──────────────────────────────────────────────────────────
  document.getElementById('s2Back').addEventListener('click', () => {
    hide('s2'); show('s1'); setStep(1);
  });

  // ── Step 2 Submit ─────────────────────────────────────────────────────────
  document.getElementById('s2Submit').addEventListener('click', async () => {
    const justification = document.getElementById('justification').value.trim();
    if (isOutside && justification.length < 20) {
      document.getElementById('justification').classList.add('err');
      document.getElementById('errJust').classList.add('show');
      document.getElementById('justification').focus();
      return;
    }
    document.getElementById('justification').classList.remove('err');
    document.getElementById('errJust').classList.remove('show');

    hide('s2'); show('s3'); setStep(3);

    const action   = document.getElementById('actionType').value;
    const userId   = document.getElementById('userId').value.trim();
    const fileName = document.getElementById('fileName').value.trim();
    const endpoint = action === 'login' ? '/log' : '/log/action';

    const payload = {
      userId,
      action,
      fileName:      fileName || null,
      justification: justification || null,
      latitude:      coords.lat,
      longitude:     coords.lon,
      deviceInfo:    navigator.userAgent
    };

    try {
      const res    = await fetch(endpoint, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload) });
      const result = await res.json();

      if (result.needsJustification) {
        // Shouldn't reach here but handle gracefully
        hide('s3'); show('s2'); setStep(2);
        document.getElementById('justWrap').style.display = 'block';
        document.getElementById('locPill').className = 'loc-pill outside';
        document.getElementById('locText').textContent = 'Outside office — justification required';
        const btn = document.getElementById('s2Submit');
        btn.disabled = false;
        btn.textContent = 'LOG & CONTINUE';
        isOutside = true;
        return;
      }

      if (result.logged || result.id) {
        showSuccess(result.risk || 'low', action);
      } else {
        throw new Error('Unexpected');
      }
    } catch {
      hide('s3'); show('s2'); setStep(2);
      const btn = document.getElementById('s2Submit');
      btn.disabled = false; btn.textContent = 'RETRY';
      document.getElementById('locPill').className = 'loc-pill outside';
      document.getElementById('locText').textContent = '⚠ Could not reach server — check connection';
      toast('Could not reach server', 'danger');
    }
  });

  function showSuccess(risk, action) {
    hide('formScreen');
    const ss = document.getElementById('successScreen');
    ss.style.display = 'block';
    document.getElementById('riskPill').className = 'risk-pill ' + risk;
    document.getElementById('riskPill').textContent = 'RISK LEVEL: ' + risk.toUpperCase();
    const msgs = { login:'Your check-in has been recorded.\nYou can now open Google Drive.', download:'Download has been logged.\nYou can now access Google Drive.', upload:'Upload has been logged.\nYou can now access Google Drive.' };
    document.getElementById('successSub').innerHTML = (msgs[action]||msgs.login).replace('\n','<br>');
  }

  document.getElementById('logAgain').addEventListener('click', () => {
    document.getElementById('successScreen').style.display = 'none';
    show('formScreen');
    hide('s2'); hide('s3'); show('s1'); setStep(1);
    document.getElementById('justification').value = '';
    document.getElementById('fileName').value = '';
    document.getElementById('justWrap').style.display = 'none';
  });

})();