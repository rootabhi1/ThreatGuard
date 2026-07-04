/* Admin console: tabs, modals, CRUD orchestration. */
(async function () {
  'use strict';

  const me = await Auth.requireRole(['admin']);
  if (!me) return;

  const esc = UI.escapeHtml;

  // =========================================================================
  //  Tab switching (uses .active class — defined in app.css)
  // =========================================================================
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
      document.getElementById('tab-' + btn.dataset.tab).classList.remove('hidden');
      if (btn.dataset.tab === 'releases') loadReleases();
      if (btn.dataset.tab === 'audit') loadAudit();
    });
  });

  // Honor ?tab=… URL param (so sidebar deep-links work)
  const urlTab = new URLSearchParams(window.location.search).get('tab');
  if (urlTab) {
    const btn = document.querySelector(`.tab[data-tab="${urlTab}"]`);
    if (btn) btn.click();
  }

  // =========================================================================
  //  Modal helpers
  // =========================================================================
  function showModal(id) { document.getElementById(id).classList.remove('hidden'); }
  function hideModal(id) { document.getElementById(id).classList.add('hidden'); }
  // Close handlers wired globally in ui.js, so just provide showModal/hideModal here.

  // =========================================================================
  //  USERS
  // =========================================================================
  let allFeatures = [];

  async function loadUsers() {
    const r = await Auth.fetch('/api/users');
    const tbody = document.getElementById('users-tbody');
    if (!r.ok) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center" style="padding: 1.5rem; color: var(--c-critical);">Failed to load users</td></tr>`;
      return;
    }
    const users = await r.json();
    if (users.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center text-light" style="padding: 1.5rem;">No users yet</td></tr>';
      return;
    }
    tbody.innerHTML = users.map(u => `
      <tr>
        <td><strong>${esc(u.email)}</strong></td>
        <td>${esc(u.full_name || '—')}</td>
        <td><span class="role-badge role-${esc(u.role)}">${esc(u.role)}</span></td>
        <td>${u.is_active ? '<span class="status status-mitigated">Active</span>' : '<span class="status status-false_positive">Inactive</span>'}</td>
        <td class="text-light text-xs">${(u.created_at || '').slice(0, 10)}</td>
        <td class="text-right">
          ${u.id === me.user.id ? '<span class="text-light text-xs">(you)</span>' :
            `<button data-edit-user="${u.id}" class="btn btn-sm btn-ghost">Edit</button>`}
        </td>
      </tr>
    `).join('');

    document.querySelectorAll('[data-edit-user]').forEach(btn => {
      btn.addEventListener('click', () => openEditUser(parseInt(btn.dataset.editUser), users));
    });
  }

  async function loadAllFeaturesIntoCache() {
    const r = await Auth.fetch('/api/features');
    if (r.ok) allFeatures = await r.json();
  }

  function renderFeatureCheckboxes(containerId, selectedIds) {
    const container = document.getElementById(containerId);
    if (allFeatures.length === 0) {
      container.innerHTML = '<p class="text-sm text-light">No features yet. Create some in the Releases tab.</p>';
      return;
    }
    container.innerHTML = allFeatures.map(f => `
      <label class="flex items-center gap-2 text-sm" style="cursor: pointer;">
        <input type="checkbox" value="${f.id}" ${selectedIds.includes(f.id) ? 'checked' : ''} />
        <span style="font-weight: 500;">${esc(f.name)}</span>
        <span class="text-light text-xs">${esc(f.description || '')}</span>
      </label>
    `).join('');
  }

  document.getElementById('btn-new-user').addEventListener('click', async () => {
    document.getElementById('form-new-user').reset();
    document.getElementById('new-user-error').classList.add('hidden');
    await loadAllFeaturesIntoCache();
    renderFeatureCheckboxes('feature-checkboxes', []);
    onRoleChange();
    showModal('modal-new-user');
  });

  function onRoleChange() {
    const role = document.getElementById('new-user-role').value;
    const wrapper = document.getElementById('feature-access-wrapper');
    // Only User-role accounts care about feature access
    wrapper.style.display = role === 'user' ? '' : 'none';
  }
  document.getElementById('new-user-role').addEventListener('change', onRoleChange);

  document.getElementById('form-new-user').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errBox = document.getElementById('new-user-error');
    errBox.classList.add('hidden');
    const fd = new FormData(e.target);
    const role = fd.get('role');
    const featureIds = role === 'user'
      ? Array.from(document.querySelectorAll('#feature-checkboxes input:checked')).map(cb => parseInt(cb.value))
      : [];
    const body = {
      email: fd.get('email').trim(),
      password: fd.get('password'),
      full_name: fd.get('full_name').trim(),
      role: role,
      feature_ids: featureIds,
    };
    const r = await Auth.fetch('/api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      const data = await r.json().catch(() => ({}));
      errBox.textContent = UI.formatApiError(data, 'Failed to create user');
      errBox.classList.remove('hidden');
      return;
    }
    hideModal('modal-new-user');
    UI.toast('User created', 'success');
    loadUsers();
  });

  // ---- Edit user
  let editingUserId = null;

  async function openEditUser(uid, allUsers) {
    editingUserId = uid;
    const user = allUsers.find(u => u.id === uid);
    if (!user) return;
    document.getElementById('edit-user-email').textContent = user.email;
    document.getElementById('edit-user-role').value = user.role;
    document.getElementById('edit-user-error').classList.add('hidden');
    document.getElementById('edit-user-msg').classList.add('hidden');
    // Load grants
    const accessR = await Auth.fetch(`/api/users/${uid}/feature-access`);
    const accessList = accessR.ok ? await accessR.json() : [];
    const accessIds = accessList.map(a => a.feature_id);
    await loadAllFeaturesIntoCache();
    renderFeatureCheckboxes('edit-feature-checkboxes', accessIds);
    showModal('modal-edit-user');
  }

  document.getElementById('btn-save-user').addEventListener('click', async () => {
    const errBox = document.getElementById('edit-user-error');
    const msgBox = document.getElementById('edit-user-msg');
    errBox.classList.add('hidden');
    msgBox.classList.add('hidden');

    // Save role
    const newRole = document.getElementById('edit-user-role').value;
    const r = await Auth.fetch(`/api/users/${editingUserId}/role`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: newRole }),
    });
    if (!r.ok) {
      const data = await r.json().catch(() => ({}));
      errBox.textContent = UI.formatApiError(data, 'Failed to update role');
      errBox.classList.remove('hidden');
      return;
    }

    // Save feature access
    const ids = Array.from(document.querySelectorAll('#edit-feature-checkboxes input:checked'))
      .map(cb => parseInt(cb.value));
    const r2 = await Auth.fetch(`/api/users/${editingUserId}/feature-access`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ feature_ids: ids }),
    });
    if (!r2.ok) {
      const data = await r2.json().catch(() => ({}));
      errBox.textContent = UI.formatApiError(data, 'Failed to update feature access');
      errBox.classList.remove('hidden');
      return;
    }
    msgBox.textContent = 'Saved.';
    msgBox.classList.remove('hidden');
    UI.toast('User updated', 'success');
    loadUsers();
  });

  document.getElementById('btn-deactivate-user').addEventListener('click', () => {
    UI.confirmDialog('Deactivate this user? They will be unable to log in.', async () => {
      const r = await Auth.fetch(`/api/users/${editingUserId}`, { method: 'DELETE' });
      if (!r.ok) {
        const data = await r.json().catch(() => ({}));
        document.getElementById('edit-user-error').textContent =
          UI.formatApiError(data, 'Failed to deactivate');
        document.getElementById('edit-user-error').classList.remove('hidden');
        return;
      }
      hideModal('modal-edit-user');
      UI.toast('User deactivated', 'success');
      loadUsers();
    });
  });

  // =========================================================================
  //  RELEASES & FEATURES
  // =========================================================================
  let selectedReleaseId = null;

  async function loadReleases() {
    const r = await Auth.fetch('/api/releases');
    if (!r.ok) {
      document.getElementById('releases-list').innerHTML = '<p class="text-sm" style="color: var(--c-critical);">Failed to load</p>';
      return;
    }
    const releases = await r.json();
    if (releases.length === 0) {
      document.getElementById('releases-list').innerHTML =
        '<p class="text-sm text-light">No releases yet. Click "+ New release".</p>';
      document.getElementById('features-list').innerHTML =
        '<p class="text-sm text-light">Create a release first.</p>';
      document.getElementById('btn-new-feature').disabled = true;
      return;
    }
    document.getElementById('releases-list').innerHTML = releases.map(r => `
      <div class="card card-hover cursor-pointer ${selectedReleaseId === r.id ? 'card-active' : ''}"
           data-release-id="${r.id}" style="padding: 0.875rem;">
        <div class="flex justify-between items-start">
          <div style="flex: 1; min-width: 0;">
            <div style="font-weight: 600;">${esc(r.name)}</div>
            <div class="text-xs text-light" style="margin-top: 2px;">${esc(r.description || '')}</div>
            ${r.target_date ? `<div class="text-xs text-light" style="margin-top: 4px;">📅 ${esc(r.target_date)}</div>` : ''}
          </div>
          <span class="status status-${r.status === 'released' ? 'mitigated' : r.status === 'cancelled' ? 'false_positive' : 'in_progress'}">${esc(r.status)}</span>
        </div>
      </div>
    `).join('');

    document.querySelectorAll('[data-release-id]').forEach(card => {
      card.addEventListener('click', () => {
        selectedReleaseId = parseInt(card.dataset.releaseId);
        loadReleases();   // re-render to show active state
        loadFeaturesForRelease(selectedReleaseId);
        document.getElementById('btn-new-feature').disabled = false;
        const rel = releases.find(r => r.id === selectedReleaseId);
        document.getElementById('selected-release-label').textContent =
          rel ? `Features in "${rel.name}"` : '';
      });
    });
  }

  async function loadFeaturesForRelease(rid) {
    const r = await Auth.fetch(`/api/features?release_id=${rid}`);
    if (!r.ok) return;
    const features = await r.json();
    const list = document.getElementById('features-list');
    if (features.length === 0) {
      list.innerHTML = '<p class="text-sm text-light">No features in this release yet.</p>';
      return;
    }
    list.innerHTML = features.map(f => `
      <div class="card" style="padding: 0.875rem;">
        <div class="flex justify-between items-start">
          <div style="flex: 1; min-width: 0;">
            <div style="font-weight: 600;">${esc(f.name)}</div>
            <div class="text-xs text-light" style="margin-top: 2px;">${esc(f.description || '')}</div>
            ${f.target_date ? `<div class="text-xs text-light" style="margin-top: 4px;">📅 Target: <strong>${esc(f.target_date)}</strong></div>` : ''}
          </div>
          <span class="status status-${f.status === 'released' ? 'mitigated' : f.status === 'cancelled' ? 'false_positive' : 'in_progress'}" style="margin-left: 8px;">${esc(f.status)}</span>
        </div>
      </div>
    `).join('');
  }

  document.getElementById('btn-new-release').addEventListener('click', () => {
    document.getElementById('form-new-release').reset();
    showModal('modal-new-release');
  });

  document.getElementById('form-new-release').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const r = await Auth.fetch('/api/releases', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: fd.get('name'),
        description: fd.get('description') || '',
        status: fd.get('status') || 'planned',
        target_date: fd.get('target_date') || null,
      }),
    });
    if (!r.ok) {
      const data = await r.json().catch(() => ({}));
      UI.toast(UI.formatApiError(data, 'Failed to create release'), 'error');
      return;
    }
    hideModal('modal-new-release');
    UI.toast('Release created', 'success');
    loadReleases();
  });

  document.getElementById('btn-new-feature').addEventListener('click', async () => {
    document.getElementById('form-new-feature').reset();
    const r = await Auth.fetch('/api/releases');
    const releases = r.ok ? await r.json() : [];
    const sel = document.getElementById('feat-release-select');
    sel.innerHTML = '<option value="">Select a release...</option>' +
      releases.map(r => `<option value="${r.id}">${esc(r.name)}</option>`).join('');
    if (selectedReleaseId) sel.value = selectedReleaseId;
    showModal('modal-new-feature');
  });

  document.getElementById('form-new-feature').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const r = await Auth.fetch('/api/features', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        release_id: parseInt(fd.get('release_id')),
        name: fd.get('name'),
        description: fd.get('description') || '',
        status: fd.get('status') || 'draft',
        target_date: fd.get('target_date') || null,
      }),
    });
    if (!r.ok) {
      const data = await r.json().catch(() => ({}));
      UI.toast(UI.formatApiError(data, 'Failed to create feature'), 'error');
      return;
    }
    hideModal('modal-new-feature');
    UI.toast('Feature created', 'success');
    if (selectedReleaseId) loadFeaturesForRelease(selectedReleaseId);
  });

  // =========================================================================
  //  AUDIT LOG
  // =========================================================================
  async function loadAudit() {
    const r = await Auth.fetch('/api/audit-log?limit=200');
    if (!r.ok) {
      document.getElementById('audit-tbody').innerHTML =
        '<tr><td colspan="6" class="text-center" style="padding: 1.5rem; color: var(--c-critical);">Failed to load audit log</td></tr>';
      return;
    }
    const logs = await r.json();
    document.getElementById('audit-count').textContent = `(${logs.length} most recent)`;
    const tbody = document.getElementById('audit-tbody');
    if (logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center text-light" style="padding: 1.5rem;">No log entries</td></tr>';
      return;
    }
    tbody.innerHTML = logs.map(l => `
      <tr>
        <td class="text-xs text-light">${(l.timestamp || '').slice(0, 19).replace('T', ' ')}</td>
        <td class="text-xs">${esc(l.user_email || '—')}</td>
        <td class="text-xs"><code style="font-family: var(--font-mono, monospace); font-size: 0.75rem;">${esc(l.action)}</code></td>
        <td><span class="status status-${l.decision === 'grant' ? 'mitigated' : 'open'}">${esc(l.decision)}</span></td>
        <td class="text-xs text-light">${esc(l.resource_type || '—')}${l.resource_id ? '#' + l.resource_id : ''}</td>
        <td class="text-xs text-light" style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${esc(l.detail || '')}">${esc(l.detail || '')}</td>
      </tr>
    `).join('');
  }

  document.getElementById('btn-refresh-audit').addEventListener('click', loadAudit);

  // =========================================================================
  //  Boot
  // =========================================================================
  loadUsers();
})();
