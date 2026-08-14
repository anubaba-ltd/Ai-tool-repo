async function copyText(id) {
  const el = document.getElementById(id);
  const text = el ? el.innerText : '';
  await navigator.clipboard.writeText(text);
  alert('Copied');
}
async function trackTool(id) {
  try { await fetch('/tools/' + id + '/track', { method: 'POST' }); } catch(e) {}
}
