/* UI helpers: toasts, animated number counters, ring chart renderer, modals. */
(function () {
  'use strict';

  /* === Toast notifications === */
  function ensureToastHost() {
    let host = document.getElementById('toast-host');
    if (!host) {
      host = document.createElement('div');
      host.id = 'toast-host';
      document.body.appendChild(host);
    }
    return host;
  }

  function toast(message, type = 'info', timeout = 3500) {
    const host = ensureToastHost();
    const el = document.createElement('div');
    el.className = 'toast ' + type;
    const icons = {
      success: '<svg class="w-5 h-5 text-green-600" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>',
      error: '<svg class="w-5 h-5 text-red-600" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>',
      warning: '<svg class="w-5 h-5 text-amber-600" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>',
      info: '<svg class="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>',
    };
    el.innerHTML = `
      ${icons[type] || icons.info}
      <span class="text-sm text-slate-800 flex-1">${escapeHtml(message)}</span>
      <button class="text-slate-400 hover:text-slate-600 text-lg leading-none">&times;</button>
    `;
    el.querySelector('button').addEventListener('click', () => removeToast(el));
    host.appendChild(el);
    setTimeout(() => removeToast(el), timeout);
  }

  function removeToast(el) {
    if (!el.parentNode) return;
    el.style.animation = 'slideInRight 0.25s ease-out reverse';
    setTimeout(() => el.remove(), 250);
  }

  /* === Animated number counter === */
  function animateCount(el, target, duration = 800) {
    const start = parseFloat(el.textContent.replace(/[^0-9.-]/g, '')) || 0;
    const startTime = performance.now();
    function step(now) {
      const t = Math.min((now - startTime) / duration, 1);
      // ease-out-cubic
      const eased = 1 - Math.pow(1 - t, 3);
      const value = Math.round(start + (target - start) * eased);
      el.textContent = value;
      if (t < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  /* === Ring chart (SVG, animated) === */
  function renderRingChart(svg, segments, total, options = {}) {
    const size = options.size || 120;
    const stroke = options.stroke || 14;
    const r = (size - stroke) / 2;
    const c = 2 * Math.PI * r;
    svg.setAttribute('viewBox', `0 0 ${size} ${size}`);
    svg.setAttribute('width', size);
    svg.setAttribute('height', size);

    let html = `
      <circle cx="${size/2}" cy="${size/2}" r="${r}" fill="none" stroke="#e2e8f0" stroke-width="${stroke}"/>
    `;
    let offset = 0;
    const colors = {
      Critical: '#dc2626',
      High: '#ea580c',
      Medium: '#ca8a04',
      Low: '#2563eb',
      Info: '#64748b',
    };
    if (total > 0) {
      Object.entries(segments).forEach(([sev, count]) => {
        if (count <= 0) return;
        const length = (count / total) * c;
        html += `
          <circle class="ring-chart-segment" cx="${size/2}" cy="${size/2}" r="${r}" fill="none"
                  stroke="${colors[sev] || '#94a3b8'}"
                  stroke-width="${stroke}"
                  stroke-dasharray="${length} ${c}"
                  stroke-dashoffset="${-offset}"
                  stroke-linecap="butt"
                  transform="rotate(-90 ${size/2} ${size/2})"
                  style="transition: stroke-dashoffset 0.8s ease, stroke-dasharray 0.8s ease;"/>
        `;
        offset += length;
      });
    }
    html += `
      <text x="${size/2}" y="${size/2}" text-anchor="middle" dominant-baseline="central"
            font-size="${size/4}" font-weight="700" fill="#0f172a">${total}</text>
      <text x="${size/2}" y="${size/2 + size/5.5}" text-anchor="middle" dominant-baseline="central"
            font-size="${size/12}" fill="#64748b" letter-spacing="0.05em">THREATS</text>
    `;
    svg.innerHTML = html;
  }

  /* === Modal management === */
  function showModal(id) {
    const m = document.getElementById(id);
    if (m) m.classList.remove('hidden');
  }
  function hideModal(id) {
    const m = document.getElementById(id);
    if (m) m.classList.add('hidden');
  }
  // Wire close buttons globally
  document.addEventListener('click', (e) => {
    if (e.target.matches('[data-close-modal]') || e.target.closest('[data-close-modal]')) {
      const modal = e.target.closest('.modal');
      if (modal) modal.classList.add('hidden');
    }
    // Backdrop click — clicking the modal container (not the card inside) closes
    if (e.target.classList && e.target.classList.contains('modal') && !e.target.classList.contains('hidden')) {
      e.target.classList.add('hidden');
    }
  });
  // ESC closes modals
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal:not(.hidden)').forEach(m => m.classList.add('hidden'));
    }
  });

  /* === Confirmation dialog === */
  function confirmDialog(message, onConfirm, onCancel) {
    const id = 'confirm-dialog-' + Date.now();
    const html = `
      <div id="${id}" class="modal">
        <div class="modal-card" style="max-width: 28rem;">
          <div class="modal-body">
            <div class="flex items-start gap-4">
              <div class="w-12 h-12 rounded-full bg-amber-100 flex items-center justify-center flex-shrink-0">
                <svg class="w-6 h-6 text-amber-600" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                </svg>
              </div>
              <div class="flex-1">
                <h3 class="text-lg font-semibold mb-1">Confirm</h3>
                <p class="text-sm" style="color: var(--c-text-light);">${escapeHtml(message)}</p>
              </div>
            </div>
            <div class="flex justify-end gap-2 mt-6">
              <button class="cancel-btn btn btn-ghost">Cancel</button>
              <button class="confirm-btn btn btn-danger">Confirm</button>
            </div>
          </div>
        </div>
      </div>
    `;
    const wrapper = document.createElement('div');
    wrapper.innerHTML = html;
    const dialog = wrapper.firstElementChild;
    document.body.appendChild(dialog);
    dialog.querySelector('.cancel-btn').addEventListener('click', () => {
      dialog.remove();
      if (onCancel) onCancel();
    });
    dialog.querySelector('.confirm-btn').addEventListener('click', () => {
      dialog.remove();
      if (onConfirm) onConfirm();
    });
  }

  function escapeHtml(s) {
    if (s == null) return '';
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]);
  }

  /* === Format an API error response into a user-friendly string ===
     Handles:
       - FastAPI/Starlette plain string: { detail: "Invalid credentials" }
       - Pydantic 422 list:              { detail: [{ loc: [...], msg: "..." }] }
       - Network/JSON-parse failures
  */
  function formatApiError(data, fallback = 'Request failed') {
    if (!data) return fallback;
    if (typeof data === 'string') return data;
    const d = data.detail;
    if (typeof d === 'string') return d;
    if (Array.isArray(d) && d.length > 0) {
      // Pydantic validation errors — show field + message
      return d.map(err => {
        const loc = Array.isArray(err.loc) ? err.loc.filter(p => p !== 'body').join('.') : '';
        const msg = err.msg || 'Invalid value';
        return loc ? `${loc}: ${msg}` : msg;
      }).join('; ');
    }
    if (d && typeof d === 'object' && d.msg) return d.msg;
    return fallback;
  }

  /* === Authenticated file download === */
  async function downloadFile(url, suggestedFilename) {
    try {
      const r = await window.Auth.fetch(url);
      if (!r.ok) {
        const err = await r.json().catch(() => ({}));
        throw new Error(err.detail || `Download failed (${r.status})`);
      }
      // Try to read filename from Content-Disposition
      const disp = r.headers.get('Content-Disposition') || '';
      const m = disp.match(/filename="?([^";]+)"?/);
      const filename = (m && m[1]) || suggestedFilename || 'report';

      const blob = await r.blob();
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
    } catch (err) {
      toast(err.message || 'Download failed', 'error');
      throw err;
    }
  }

  window.UI = {
    toast,
    animateCount,
    renderRingChart,
    showModal,
    hideModal,
    confirmDialog,
    escapeHtml,
    downloadFile,
    formatApiError,
  };
})();
