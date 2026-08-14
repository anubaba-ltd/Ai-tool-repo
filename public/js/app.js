function showToast(message) {
  let toast = document.querySelector('.toast-copy');
  if (!toast) {
    toast = document.createElement('div');
    toast.className = 'toast-copy';
    document.body.appendChild(toast);
  }
  toast.textContent = message;
  toast.classList.add('show');
  clearTimeout(window.__copyToastTimer);
  window.__copyToastTimer = setTimeout(() => toast.classList.remove('show'), 2200);
}

async function copyText(id) {
  const el = document.getElementById(id);
  const text = el ? el.innerText.trim() : '';
  if (!text) return showToast('Nothing to copy');
  try {
    await navigator.clipboard.writeText(text);
    showToast('Access text copied');
  } catch (err) {
    showToast('Copy failed');
  }
}

async function trackTool(id) {
  try { await fetch('/tools/' + id + '/track', { method: 'POST' }); } catch(e) {}
}

document.addEventListener('DOMContentLoaded', () => {
  const path = window.location.pathname;
  document.querySelectorAll('.sidebar-link').forEach(link => {
    const href = link.getAttribute('href');
    if (href && (href === path || (href !== '/admin' && path.startsWith(href)))) {
      link.classList.add('active');
    }
  });

  document.querySelectorAll('.card, .hero, .page-toolbar').forEach((el, index) => {
    el.classList.add('reveal');
    el.style.animationDelay = Math.min(index * 0.035, 0.28) + 's';
  });

  document.querySelectorAll('[data-table-search]').forEach(input => {
    input.addEventListener('input', () => {
      const table = document.querySelector(input.dataset.tableSearch);
      if (!table) return;
      const query = input.value.toLowerCase().trim();
      table.querySelectorAll('tbody tr').forEach(row => {
        row.style.display = row.innerText.toLowerCase().includes(query) ? '' : 'none';
      });
    });
  });
});
