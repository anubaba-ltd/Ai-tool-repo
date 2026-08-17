function showToast(message) {
  let toast = document.querySelector('.toast-copy');
  if (!toast) { toast = document.createElement('div'); toast.className = 'toast-copy'; document.body.appendChild(toast); }
  toast.textContent = message; toast.classList.add('show'); clearTimeout(window.__copyToastTimer); window.__copyToastTimer = setTimeout(() => toast.classList.remove('show'), 2200);
}
async function copyText(id) { const el=document.getElementById(id); const text=el?el.innerText.trim():''; if(!text)return showToast('Nothing to copy'); try{await navigator.clipboard.writeText(text);showToast('Access text copied');}catch(e){showToast('Copy failed');} }
async function trackTool(id) { try { await fetch('/tools/' + id + '/track', { method: 'POST' }); } catch(e) {} }

const ExtensionSecurity = (() => {
  const SOURCE = 'AIANUBABA_PORTAL';
  const REPLY_SOURCE = 'AIANUBABA_EXTENSION';
  let serverMisses = 0;
  let loggingOut = false;

  function status(text, state='checking') {
    const el = document.getElementById('extensionSecurityStatus'); if (!el) return;
    const icon = state === 'active' ? 'fa-circle-check' : state === 'error' ? 'fa-circle-xmark' : 'fa-shield-halved';
    el.innerHTML = `<i class="fa-solid ${icon}"></i> ${text}`;
    el.style.opacity = state === 'checking' ? '.75' : '1';
  }

  function request(type, payload = {}, timeout = 1400) {
    return new Promise((resolve, reject) => {
      const requestId = (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`);
      const timer = setTimeout(() => { cleanup(); reject(new Error('EXTENSION_NOT_RESPONDING')); }, timeout);
      function onMessage(event) {
        if (event.source !== window || event.origin !== window.location.origin) return;
        const d = event.data || {};
        if (d.source !== REPLY_SOURCE || d.type !== 'RESPONSE' || d.requestId !== requestId) return;
        cleanup(); resolve(d.payload || {});
      }
      function cleanup() { clearTimeout(timer); window.removeEventListener('message', onMessage); }
      window.addEventListener('message', onMessage);
      window.postMessage({ source: SOURCE, type, requestId, payload }, window.location.origin);
    });
  }

  async function forcedLogout(reason) {
    if (loggingOut) return; loggingOut = true;
    status('Extension unavailable — signing out', 'error');
    try { await fetch('/api/session/extension-missing', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({reason}), credentials:'same-origin', keepalive:true }); } catch (_) {}
    window.location.replace('/login?extension=missing');
  }

  async function activate() {
    status('Checking extension...', 'checking');
    try {
      const presence = await request('PRESENCE', {}, 1200);
      if (!presence?.ok) return forcedLogout('presence_failed');
    } catch (_) { return forcedLogout('extension_not_installed_or_disabled'); }

    let bootstrap;
    try {
      const r = await fetch('/api/extension/bootstrap', { credentials:'same-origin', cache:'no-store' });
      if (!r.ok) { window.location.replace('/login?session=expired'); return false; }
      bootstrap = await r.json();
    } catch (_) { status('Portal temporarily unavailable', 'error'); return false; }

    try {
      const result = await request('ACTIVATE', { activationToken: bootstrap.activationToken }, 3500);
      if (!result?.ok) {
        if (result?.transient) { status('Network check pending...', 'checking'); return false; }
        return forcedLogout(result?.code || 'activation_failed');
      }
      serverMisses = 0; status('Tool Active', 'active'); return true;
    } catch (_) { return forcedLogout('extension_activation_no_response'); }
  }

  async function heartbeat(reason='portal-5sec', force=true) {
    try {
      const result = await request('HEARTBEAT', { reason, force }, 1800);
      if (result?.ok) { serverMisses = 0; status('Tool Active', 'active'); return true; }
      if (result?.transient) {
        serverMisses += 1; status('Checking secure session...', 'checking');
        if (serverMisses >= 3) await forcedLogout('heartbeat_network_timeout');
        return false;
      }
      await forcedLogout(result?.code || 'heartbeat_invalid'); return false;
    } catch (_) { await forcedLogout('extension_disabled_or_removed'); return false; }
  }

  async function launch(url, toolId) {
    const ok = await heartbeat('before-tool-launch', true); if (!ok) return false;
    try {
      const result = await request('LAUNCH', { url }, 8000);
      if (!result?.ok) {
        if (result?.transient) return showToast('Secure server check is temporarily unavailable. Try again.');
        await forcedLogout(result?.code || 'launch_denied'); return false;
      }
      if (toolId) trackTool(toolId); showToast('Secure session verified'); return true;
    } catch (_) { await forcedLogout('extension_launch_no_response'); return false; }
  }

  async function init() {
    if (window.location.pathname !== '/dashboard') return;
    await activate();
    setInterval(() => heartbeat('portal-5sec', true), 5000);
    window.addEventListener('pageshow', () => heartbeat('page-refresh-pageshow', true), true);
    window.addEventListener('focus', () => heartbeat('portal-focus', true), true);
    document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') heartbeat('portal-visible', true); }, true);
    window.addEventListener('message', (event) => {
      if (event.source !== window || event.origin !== window.location.origin) return;
      const d = event.data || {};
      if (d.source === REPLY_SOURCE && d.type === 'AUTH_EVENT' && d.payload && !d.payload.ok && !d.payload.transient) forcedLogout(d.payload.code || 'extension_auth_event');
    });
  }
  return { init, heartbeat, launch };
})();

document.addEventListener('DOMContentLoaded', () => {
  const path = window.location.pathname;
  document.querySelectorAll('.sidebar-link').forEach(link => { const href=link.getAttribute('href'); if(href&&(href===path||(href!=='/admin'&&path.startsWith(href)))) link.classList.add('active'); });
  document.querySelectorAll('.card, .hero, .page-toolbar').forEach((el,index)=>{el.classList.add('reveal');el.style.animationDelay=Math.min(index*0.035,0.28)+'s';});
  document.querySelectorAll('[data-table-search]').forEach(input=>{input.addEventListener('input',()=>{const table=document.querySelector(input.dataset.tableSearch);if(!table)return;const query=input.value.toLowerCase().trim();table.querySelectorAll('tbody tr').forEach(row=>{row.style.display=row.innerText.toLowerCase().includes(query)?'':'none';});});});

  document.querySelectorAll('a[data-secure-tool="1"]').forEach(link => {
    link.addEventListener('click', async (e) => {
      e.preventDefault(); e.stopPropagation();
      link.classList.add('disabled'); link.setAttribute('aria-disabled','true');
      try { await ExtensionSecurity.launch(link.href, link.dataset.toolId); }
      finally { link.classList.remove('disabled'); link.removeAttribute('aria-disabled'); }
    });
  });
  ExtensionSecurity.init();
});
