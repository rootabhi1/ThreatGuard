/* User dashboard — list, create, detail with DFD + threat metadata. */
(async function () {
  'use strict';

  const me = await Auth.requireRole(['user', 'admin']);
  if (!me) return;

  const esc = UI.escapeHtml;
  let allTMs = [];
  let allFeatures = [];
  let allTemplates = [];
  let selectedTemplate = null;   // when set, create uses this structured system directly
  let jiraConfigured = false;    // gates the per-threat "Create Jira ticket" button
  let llmConfigured = false;     // gates the per-threat "AI Fix" button

  // =========================================================================
  //  Load
  // =========================================================================
  async function loadAll() {
    const [tmResp, featResp] = await Promise.all([
      Auth.fetch('/api/threat-models'),
      Auth.fetch('/api/features'),
    ]);
    if (!tmResp.ok) {
      UI.toast('Failed to load threat models', 'error');
      return;
    }
    allTMs = await tmResp.json();
    allFeatures = featResp.ok ? await featResp.json() : [];
    renderStats();
    renderList();
  }

  function renderStats() {
    UI.animateCount(document.getElementById('stat-total'), allTMs.length);
    UI.animateCount(document.getElementById('stat-threats'), 0);
    UI.animateCount(document.getElementById('stat-open'), 0);
    UI.animateCount(document.getElementById('stat-mitigated'), 0);

    // Aggregate from full TM details (background)
    (async () => {
      let threats = 0, open = 0, mitigated = 0;
      const results = await Promise.all(
        allTMs.map(t => Auth.fetch('/api/threat-models/' + t.id).then(r => r.ok ? r.json() : null).catch(() => null))
      );
      for (const tm of results) {
        if (!tm || !tm.analysis) continue;
        threats += tm.analysis.summary.total || 0;
        const statuses = tm.threat_statuses || {};
        for (const t of tm.analysis.threats || []) {
          const s = (statuses[t.id] && statuses[t.id].status) || 'open';
          if (s === 'open') open++;
          else if (s === 'mitigated') mitigated++;
        }
      }
      UI.animateCount(document.getElementById('stat-threats'), threats);
      UI.animateCount(document.getElementById('stat-open'), open);
      UI.animateCount(document.getElementById('stat-mitigated'), mitigated);
    })();
  }

  function renderList() {
    const container = document.getElementById('tm-list');
    const empty = document.getElementById('empty-state');
    if (allTMs.length === 0) {
      container.classList.add('hidden');
      empty.classList.remove('hidden');
      return;
    }
    container.classList.remove('hidden');
    empty.classList.add('hidden');

    const featureMap = {};
    allFeatures.forEach(f => featureMap[f.id] = f);

    container.innerHTML = allTMs.map(tm => {
      const feature = featureMap[tm.feature_id];
      const featureName = feature ? feature.name : `#${tm.feature_id}`;
      const updated = (tm.updated_at || '').slice(0, 10);
      const methodologies = (tm.methodologies || []).slice(0, 4).map(m =>
        `<span class="threat-meta-tag" style="text-transform: uppercase; font-size: 0.625rem;">${m}</span>`
      ).join(' ');
      const compCount = (tm.system && tm.system.components && tm.system.components.length) || 0;

      return `
        <div class="card card-interactive card-accent p-4" data-tm-id="${tm.id}">
          <div class="flex items-center justify-between mb-2">
            <h3 class="font-bold truncate" style="font-size: 1rem;">${esc(tm.name)}</h3>
          </div>
          <div class="text-xs text-light flex items-center gap-2 mb-3">
            <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M5 8h14M5 12h14M5 16h14"/></svg>
            <span>${esc(featureName)}</span>
          </div>
          <p class="text-sm text-dim line-clamp-2 mb-3" style="min-height: 2.5em;">${esc(tm.description || 'No description')}</p>
          <div class="flex gap-1 mb-3">${methodologies}</div>
          <div class="flex items-center justify-between" style="padding-top: 0.75rem; border-top: 1px solid var(--c-surface-2); font-size: 0.75rem; color: var(--c-text-light);">
            <span class="flex items-center gap-1">
              <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15 14"/></svg>
              ${updated}
            </span>
            <span class="font-semibold" style="color: var(--c-brand);">${compCount} components →</span>
          </div>
        </div>
      `;
    }).join('');

    container.querySelectorAll('[data-tm-id]').forEach(el => {
      el.addEventListener('click', () => openDetail(parseInt(el.dataset.tmId)));
    });
  }

  // =========================================================================
  //  New TM modal
  // =========================================================================
  const canCreateFeature = Auth.hasPermission('feature.create') || (me.user && me.user.role === 'admin');

  function populateFeatureSelect() {
    const sel = document.getElementById('select-feature');
    const help = document.getElementById('feature-help');
    if (allFeatures.length === 0) {
      sel.innerHTML = '<option value="">No features available</option>';
      sel.disabled = true;
      if (canCreateFeature) {
        // Admins can unblock themselves in one click instead of hunting for the
        // Releases & Features admin screen — the #1 fresh-deploy friction point.
        help.classList.remove('field-help-error');
        help.innerHTML =
          'No features yet. ' +
          '<button type="button" id="btn-seed-workspace" class="btn btn-secondary btn-sm" style="margin:6px 0;">Create starter workspace</button> ' +
          '<span class="text-xs text-light">or set up your own in <a href="/admin" style="color:var(--c-brand);font-weight:600;">Admin → Releases &amp; Features</a>.</span>';
        const seedBtn = document.getElementById('btn-seed-workspace');
        if (seedBtn) seedBtn.addEventListener('click', createStarterWorkspace);
      } else {
        help.textContent = 'No features yet. Ask an admin to grant you access.';
        help.classList.add('field-help-error');
      }
      return;
    }
    sel.disabled = false;
    sel.innerHTML = '<option value="">Select a feature...</option>' +
      allFeatures.map(f => `<option value="${f.id}">${esc(f.name)}</option>`).join('');
    help.textContent = `${allFeatures.length} feature(s) you have access to.`;
    help.classList.remove('field-help-error');
  }

  // One-click starter workspace for admins on a deployment that has no features
  // yet (e.g. an existing install created before first-run seeding). Reuses the
  // normal release + feature endpoints, then re-populates and auto-selects it.
  async function createStarterWorkspace(e) {
    const btn = e.currentTarget;
    btn.disabled = true;
    btn.textContent = 'Creating…';
    try {
      const relResp = await Auth.fetch('/api/releases', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Initial Release',
          description: 'Starter release — rename or add your own in Admin → Releases & Features.',
        }),
      });
      if (!relResp.ok) throw new Error((await relResp.json()).detail || 'Could not create release');
      const rel = await relResp.json();
      const featResp = await Auth.fetch('/api/features', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          release_id: rel.id,
          name: 'General',
          description: 'Starter feature — a home for your first threat model.',
        }),
      });
      if (!featResp.ok) throw new Error((await featResp.json()).detail || 'Could not create feature');
      const feat = await featResp.json();
      await loadAll();
      populateFeatureSelect();
      const sel = document.getElementById('select-feature');
      if (sel) sel.value = String(feat.id);
      UI.toast('Starter workspace created — you can create a threat model now.', 'success');
    } catch (err) {
      UI.toast(err.message || 'Could not create starter workspace', 'error', 8000);
      btn.disabled = false;
      btn.textContent = 'Create starter workspace';
    }
  }

  async function updateLlmStatusBadge() {
    const badge = document.getElementById('llm-status-badge');
    const cb = document.getElementById('use-llm');
    if (!badge) return;
    try {
      const r = await fetch('/api/health');
      const data = await r.json();
      if (data.llm_configured) {
        badge.textContent = 'Available';
        badge.className = 'role-badge';
        badge.style.cssText = 'background: linear-gradient(135deg, #d1fae5, #a7f3d0); color: #065f46; font-size: 0.625rem;';
      } else {
        badge.textContent = 'Not configured';
        badge.className = 'role-badge';
        badge.style.cssText = 'background: linear-gradient(135deg, #fef3c7, #fde68a); color: #92400e; font-size: 0.625rem;';
        cb.disabled = true;
        cb.checked = false;
      }
    } catch { badge.textContent = 'Unknown'; }
  }

  // Quick-start templates (ported from the legacy canvas). Selecting one loads a
  // ready-made system so create can skip text-extraction and use it directly.
  async function loadTemplates() {
    const host = document.getElementById('template-chips');
    if (!host) return;
    if (!allTemplates.length) {
      try {
        const r = await Auth.fetch('/api/templates');
        allTemplates = r.ok ? await r.json() : [];
      } catch { allTemplates = []; }
    }
    if (!allTemplates.length) { host.innerHTML = '<span class="text-xs text-light">No templates available.</span>'; return; }
    host.innerHTML = allTemplates.map((t, i) =>
      `<button type="button" data-tpl="${i}" class="btn btn-sm btn-secondary">${esc(t.icon || '📦')} ${esc(t.name)}</button>`
    ).join('');
    host.querySelectorAll('[data-tpl]').forEach(btn =>
      btn.addEventListener('click', () => selectTemplate(parseInt(btn.dataset.tpl), btn)));
  }

  function selectTemplate(idx, btn) {
    const t = allTemplates[idx];
    if (!t) return;
    selectedTemplate = t;
    const nameInput = document.querySelector('#form-new-tm input[name="name"]');
    const sysText = document.querySelector('#form-new-tm textarea[name="system_text"]');
    if (nameInput && !nameInput.value.trim()) nameInput.value = t.name;
    if (sysText) sysText.value =
      `${t.description || t.name}\nComponents: ${(t.components || []).map(c => c.name).join(', ')}`;
    document.querySelectorAll('#template-chips [data-tpl]').forEach(b => b.classList.remove('btn-primary'));
    if (btn) { btn.classList.add('btn-primary'); }
    const note = document.getElementById('template-selected');
    if (note) {
      note.classList.remove('hidden');
      note.innerHTML = `Using template <strong>${esc(t.name)}</strong> — ${(t.components || []).length} components, ${(t.data_flows || []).length} flows. ` +
        `<button type="button" id="clear-template" class="btn btn-sm btn-ghost" style="padding:0 6px;">Clear</button>`;
      const clr = document.getElementById('clear-template');
      if (clr) clr.addEventListener('click', clearTemplate);
    }
  }

  function clearTemplate() {
    selectedTemplate = null;
    document.querySelectorAll('#template-chips [data-tpl]').forEach(b => b.classList.remove('btn-primary'));
    const note = document.getElementById('template-selected');
    if (note) { note.classList.add('hidden'); note.innerHTML = ''; }
  }

  function openNewModal() {
    const form = document.getElementById('form-new-tm');
    if (form) form.reset();
    const stride = document.querySelector('input[name="methodology"][value="stride"]');
    if (stride) stride.checked = true;
    document.getElementById('new-tm-error').classList.add('hidden');
    clearTemplate();
    loadTemplates();
    populateFeatureSelect();
    updateLlmStatusBadge();
    UI.showModal('modal-new-tm');
    // Editing the system description by hand means the user is going custom —
    // drop the template so we extract from their text instead.
    const sysText = document.querySelector('#form-new-tm textarea[name="system_text"]');
    if (sysText && !sysText._tplWired) {
      sysText._tplWired = true;
      sysText.addEventListener('input', () => { if (selectedTemplate) clearTemplate(); });
    }
  }

  document.getElementById('btn-new-tm').addEventListener('click', openNewModal);
  const btnNewEmpty = document.getElementById('btn-new-tm-empty');
  if (btnNewEmpty) btnNewEmpty.addEventListener('click', openNewModal);

  // ---- Compare (release diff) ----
  function openCompareModal() {
    const analyzed = allTMs.filter(t => t.analysis || t.methodologies);  // any saved model
    if (allTMs.length < 2) { UI.toast('You need at least two threat models to compare.', 'info'); return; }
    const opts = allTMs.map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join('');
    const a = document.getElementById('compare-a'), b = document.getElementById('compare-b');
    a.innerHTML = opts; b.innerHTML = opts;
    // The list is newest-first, so default baseline = older (last), after = newest (first).
    if (a.options.length > 1) a.selectedIndex = a.options.length - 1;
    b.selectedIndex = 0;
    document.getElementById('compare-result').innerHTML = '';
    UI.showModal('modal-compare');
  }
  document.getElementById('btn-compare').addEventListener('click', openCompareModal);

  document.getElementById('btn-run-compare').addEventListener('click', async () => {
    const a = document.getElementById('compare-a').value, b = document.getElementById('compare-b').value;
    const out = document.getElementById('compare-result');
    if (a === b) { out.innerHTML = '<p class="text-sm" style="color:var(--c-critical);">Pick two different threat models.</p>'; return; }
    out.innerHTML = '<div class="dots-loader text-brand"><span></span><span></span><span></span></div>';
    const r = await Auth.fetch(`/api/releases/${a}/diff/${b}`);
    if (!r.ok) { out.innerHTML = `<p class="text-sm" style="color:var(--c-critical);">${esc((await r.json()).detail || 'Compare failed')}</p>`; return; }
    const d = await r.json();
    const sevTag = s => `<span class="threat-meta-tag" style="font-size:0.625rem;text-transform:uppercase;">${esc(s || '')}</span>`;
    const section = (title, color, items, render) => `
      <div class="card p-3 mb-3">
        <div class="font-semibold text-sm mb-2" style="color:${color};">${title} <span class="text-light">(${items.length})</span></div>
        ${items.length ? items.map(render).join('') : '<p class="text-xs text-light">None.</p>'}
      </div>`;
    out.innerHTML = `
      <div class="flex items-center gap-2 mb-3 text-sm">
        <strong>${esc(d.model_1.name)}</strong> <span class="text-light">→</span> <strong>${esc(d.model_2.name)}</strong>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        ${section('🆕 New threats', 'var(--c-critical)', d.new_threats || [], t => `<div class="text-sm" style="margin:2px 0;">${sevTag(t.severity)} ${esc(t.title)} <span class="text-light">· ${esc(t.component_name||'')}</span></div>`)}
        ${section('✅ Resolved threats', 'var(--c-success)', d.resolved_threats || [], t => `<div class="text-sm" style="margin:2px 0;">${sevTag(t.severity)} ${esc(t.title)} <span class="text-light">· ${esc(t.component_name||'')}</span></div>`)}
        ${section('↕ Re-rated severity', '#ca8a04', d.changed_severity || [], c => `<div class="text-sm" style="margin:2px 0;">${esc(c.threat.title)}: <strong>${esc(c.old)}</strong> → <strong>${esc(c.new)}</strong></div>`)}
        ${section('🧩 Component changes', 'var(--c-brand)', [...(d.new_components||[]).map(n=>({t:'+ '+n})), ...(d.removed_components||[]).map(n=>({t:'− '+n}))], c => `<div class="text-sm" style="margin:2px 0;">${esc(c.t)}</div>`)}
      </div>`;
  });

  document.getElementById('form-new-tm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errBox = document.getElementById('new-tm-error');
    const submitBtn = document.getElementById('submit-new-tm');
    const submitLabel = submitBtn.querySelector('.submit-label');
    errBox.classList.add('hidden');
    submitBtn.disabled = true;

    const setProgress = (text) => {
      submitLabel.innerHTML = `<span class="dots-loader"><span></span><span></span><span></span></span> ${text}`;
    };

    try {
      const fd = new FormData(e.target);
      const featureId = parseInt(fd.get('feature_id'));
      const methodologies = Array.from(document.querySelectorAll('input[name="methodology"]:checked')).map(cb => cb.value);
      if (methodologies.length === 0) throw new Error('Pick at least one methodology');
      const useLlm = document.getElementById('use-llm').checked;

      let system;
      if (selectedTemplate) {
        // A ready-made template already has structured components/flows/boundaries —
        // use them directly instead of re-deriving from text.
        setProgress('Loading template...');
        system = {
          name: fd.get('name') || selectedTemplate.name,
          description: fd.get('description') || selectedTemplate.description || '',
          components: JSON.parse(JSON.stringify(selectedTemplate.components || [])),
          data_flows: JSON.parse(JSON.stringify(selectedTemplate.data_flows || [])),
          trust_boundaries: JSON.parse(JSON.stringify(selectedTemplate.trust_boundaries || [])),
        };
        system._source_text = fd.get('system_text');
      } else {
        setProgress(useLlm ? 'Extracting components with AI...' : 'Extracting components...');
        const extractResp = await Auth.fetch('/api/extract-from-text', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: fd.get('system_text'), use_llm: useLlm }),
        });
        if (!extractResp.ok) throw new Error((await extractResp.json()).detail || 'Extraction failed');
        system = await extractResp.json();
        if (!system.name) system.name = fd.get('name');
        // Stash the inference mode + source text for later display
        system._boundary_inference_mode = system.boundary_inference_mode || 'heuristic';
        system._source_text = fd.get('system_text');
        delete system.boundary_inference_mode;
      }

      setProgress('Creating threat model...');
      const createResp = await Auth.fetch('/api/threat-models', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          feature_id: featureId,
          name: fd.get('name'),
          description: fd.get('description') || '',
          system,
          methodologies,
        }),
      });
      if (!createResp.ok) throw new Error((await createResp.json()).detail || 'Create failed');
      const tm = await createResp.json();

      setProgress(useLlm ? 'Running analysis (LLM, ~30s)...' : 'Running analysis...');
      const analyzeResp = await Auth.fetch(`/api/threat-models/${tm.id}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ methodologies, use_llm: useLlm }),
      });
      if (!analyzeResp.ok) throw new Error((await analyzeResp.json()).detail || 'Analysis failed');
      const analysis = await analyzeResp.json();

      UI.hideModal('modal-new-tm');
      UI.toast(`Created "${tm.name}" — ${analysis.summary.total} threats identified`, 'success');
      // If AI enhancement was requested, tell the truth about what it did
      // instead of leaving the user to discover "LLM: No" in the report later.
      const st = analysis.llm_status;
      if (useLlm && st) {
        if (st.state === 'error')
          UI.toast(`AI enhancement failed: ${st.error}. Showing rule-based results only.`, 'error', 9000);
        else if (st.state === 'unavailable')
          UI.toast('AI enhancement was requested, but no API key is configured on the server.', 'error', 9000);
        else if (st.state === 'no_additions')
          UI.toast('AI enhancement ran — no threats beyond the rule engine for this system.', 'info');
        else if (st.state === 'enhanced')
          UI.toast(`AI enhancement added ${st.added} context-specific threat(s).`, 'success');
      }
      await loadAll();
      openDetail(tm.id);
    } catch (err) {
      errBox.textContent = err.message;
      errBox.classList.remove('hidden');
    } finally {
      submitBtn.disabled = false;
      submitLabel.textContent = 'Create & analyze';
    }
  });

  // =========================================================================
  //  Detail modal
  // =========================================================================
  let currentTM = null;
  let filter = { severity: null, status: null, search: '' };

  async function openDetail(tmId) {
    UI.showModal('modal-tm-detail');
    document.getElementById('detail-title').textContent = 'Loading...';
    document.getElementById('detail-subtitle').textContent = '';
    document.getElementById('detail-body').innerHTML = `
      <div class="text-center" style="padding: 4rem 0;">
        <div class="dots-loader text-brand" style="font-size: 2rem;"><span></span><span></span><span></span></div>
        <div class="text-sm text-light mt-3">Loading threat model...</div>
      </div>`;

    const r = await Auth.fetch('/api/threat-models/' + tmId);
    if (!r.ok) {
      document.getElementById('detail-body').innerHTML = '<p style="color: var(--c-critical);">Failed to load</p>';
      return;
    }
    currentTM = await r.json();
    filter = { severity: null, status: null, search: '' };
    renderDetail();
  }

  // ---- Analysis tab helpers (ported from the legacy canvas so these advertised
  // views live in the primary, authenticated dashboard) ----
  const SEV_HEX = { Critical: '#b91c1c', High: '#d97706', Medium: '#ca8a04', Low: '#16a34a', Info: '#0284c7' };
  const SEV_SCORE = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 };
  const sevHex = s => SEV_HEX[s] || '#64748b';

  // Likelihood × Impact grid. Impact = severity; likelihood from DREAD
  // exploitability when present, else a heuristic from severity.
  function riskMatrixHTML(analysis) {
    const threats = (analysis && analysis.threats) || [];
    const cells = {};
    threats.forEach(t => {
      const impact = SEV_SCORE[t.severity] || 2;
      const dread = t.dread;
      let likelihood = dread ? Math.round(((dread.E_exploitability || 5) / 10) * 5) : Math.ceil(impact * 0.7);
      likelihood = Math.max(1, Math.min(5, likelihood));
      (cells[`${likelihood},${impact}`] ||= []).push(t);
    });
    window._matrixData = cells;
    const LABELS = ['', 'Very Low', 'Low', 'Medium', 'High', 'Very High'];
    const cellBg = (r, c) => { const s = r * c; return s >= 16 ? '#fef2f2' : s >= 9 ? '#fff7ed' : s >= 4 ? '#fefce8' : '#f0fdf4'; };
    return `
      <div class="card p-4 mb-4">
        <div class="text-xs font-semibold text-light" style="text-transform:uppercase;letter-spacing:.05em;margin-bottom:10px;">Risk matrix — Likelihood × Impact</div>
        <div style="overflow-x:auto;">
        <table style="border-collapse:collapse;font-size:11px;min-width:360px;width:100%;">
          <thead><tr><th></th>${[1,2,3,4,5].map(c=>`<th style="padding:4px 8px;color:#475569;text-align:center;">${LABELS[c]}<br/><span style="font-size:9px;opacity:.6">Impact</span></th>`).join('')}</tr></thead>
          <tbody>
            ${[5,4,3,2,1].map(row=>`<tr>
              <td style="padding:4px 8px;color:#475569;text-align:right;white-space:nowrap;">${LABELS[row]}<br/><span style="font-size:9px;opacity:.6">Likelihood</span></td>
              ${[1,2,3,4,5].map(col=>{
                const items = cells[`${row},${col}`] || [];
                return `<td style="padding:4px;text-align:center;background:${cellBg(row,col)};border:1px solid #e2e8f0;cursor:${items.length?'pointer':'default'};"
                  ${items.length?`onclick="window._showMatrixCell('${row},${col}')"`:''} title="${esc(items.map(t=>t.title).join(', '))}">
                  ${items.length?`<span style="display:inline-block;min-width:22px;height:22px;line-height:22px;background:${sevHex(items[0].severity)};color:#fff;border-radius:50%;font-weight:600;">${items.length}</span>`:''}
                </td>`;
              }).join('')}
            </tr>`).join('')}
          </tbody>
        </table>
        </div>
        <p class="text-xs text-light" style="margin-top:6px;">Click any populated cell to list its threats. Number = threat count; colour = risk level.</p>
      </div>`;
  }

  // Multi-hop attack paths: entry components → reachable targets, ranked by criticality.
  function attackPathsHTML(analysis) {
    const threats = (analysis && analysis.threats) || [];
    const sys = (analysis && analysis.system) || {};
    const components = sys.components || [], flows = sys.data_flows || [], boundaries = sys.trust_boundaries || [];
    const compById = {}; components.forEach(c => compById[c.id] = c);
    const threatsFor = (c) => threats.filter(t => t.component_id === c.id || t.component_name === c.name);
    const entryIds = new Set(components.filter(c => ['user','external_entity','mobile_app'].includes(c.type)).map(c => c.id));
    const adj = {}; flows.forEach(f => (adj[f.from] ||= []).push({ to: f.to, flow: f }));
    const paths = [];
    entryIds.forEach(start => {
      const sc = compById[start]; if (!sc) return;
      (adj[start] || []).forEach(({ to: mid, flow: f1 }) => {
        const mc = compById[mid]; if (!mc) return;
        const crosses = boundaries.some(b => (b.contains||[]).includes(start) !== (b.contains||[]).includes(mid));
        const near = [...threatsFor(sc), ...threatsFor(mc)];
        if (!near.some(t => ['Critical','High'].includes(t.severity))) return;
        const hops = adj[mid] || [];
        if (hops.length) hops.forEach(({ to: dest }) => {
          const dc = compById[dest]; if (!dc || dest === start) return;
          const all = [...threatsFor(sc), ...threatsFor(mc), ...threatsFor(dc)];
          paths.push({ nodes: [sc, mc, dc], flows: [f1], threats: all, critCount: all.filter(t=>t.severity==='Critical').length, crosses });
        });
        else paths.push({ nodes: [sc, mc], flows: [f1], threats: near, critCount: near.filter(t=>t.severity==='Critical').length, crosses });
      });
    });
    const seen = new Set();
    const unique = paths.filter(p => { const k = p.nodes.map(n=>n.id).join('→'); if (seen.has(k)) return false; seen.add(k); return true; })
                        .sort((a,b) => b.critCount - a.critCount).slice(0, 5);
    if (!unique.length) return `<div class="card p-4"><div class="text-xs font-semibold text-light" style="text-transform:uppercase;letter-spacing:.05em;">⚡ Top attack paths</div><p class="text-sm text-light mt-2">No multi-hop attack paths with high-severity threats were found for this system.</p></div>`;
    return `
      <div class="card p-4" style="background:#fff7ed;border-color:#fed7aa;">
        <div class="text-xs font-semibold" style="color:#9a3412;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px;">⚡ Top attack paths</div>
        <p class="text-xs" style="color:#7c3012;margin:0 0 10px;">Multi-hop paths an attacker could follow through your system, ordered by severity.</p>
        ${unique.map(path=>`
          <div style="background:#fff;border:1px solid #fed7aa;border-left:3px solid ${path.critCount>0?'#e11d48':'#f97316'};border-radius:8px;padding:12px;margin-bottom:8px;">
            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px;">
              ${path.nodes.map((n,i)=>`<span style="font-size:12px;font-weight:600;color:#0f172a;background:#f8fafc;padding:3px 8px;border-radius:4px;border:1px solid #e2e8f0;">${esc(n.name)}</span>${i<path.nodes.length-1?`<span style="color:#94a3b8;">${path.flows[i]&&!path.flows[i].encrypted?'⚠→':'→'}</span>`:''}`).join('')}
              ${path.crosses?'<span style="font-size:10px;padding:2px 6px;background:#fef2f2;color:#991b1b;border-radius:99px;">crosses trust boundary</span>':''}
            </div>
            <div class="text-xs text-light">${path.threats.length} threats · ${path.critCount>0?`<span style="color:#e11d48;font-weight:600;">${path.critCount} Critical</span> · `:''}Entry: <strong>${esc(path.nodes[0].type)}</strong> → Target: <strong>${esc(path.nodes[path.nodes.length-1].type)}</strong></div>
          </div>`).join('')}
      </div>`;
  }

  window._showMatrixCell = function (key) {
    const threats = (window._matrixData || {})[key] || [];
    if (!threats.length) return;
    UI.toast(threats.map(t => `${t.severity}: ${t.title}`).join('\n'), 'info', 6000);
  };

  function renderDetail() {
    const tm = currentTM;
    const featureName = (allFeatures.find(f => f.id === tm.feature_id) || {}).name || `#${tm.feature_id}`;
    document.getElementById('detail-title').textContent = tm.name;
    document.getElementById('detail-subtitle').textContent = `${featureName} · Updated ${(tm.updated_at || '').slice(0, 10)}`;

    const analysis = tm.analysis;
    if (!analysis) {
      document.getElementById('detail-body').innerHTML = `
        <p class="text-sm text-dim mb-4">${esc(tm.description || 'No description')}</p>
        <div class="card p-6 text-center">
          <p class="text-sm text-dim mb-3">No analysis run yet on this threat model.</p>
          <button id="btn-run-analysis" class="btn btn-primary" data-tm-id="${tm.id}">Run analysis</button>
        </div>`;
      wireDetailActions();
      return;
    }

    const sev = analysis.summary.by_severity || {};
    const total = analysis.summary.total || 0;

    const body = `
      <p class="text-sm text-dim mb-6">${esc(tm.description || 'No description')}</p>

      <!-- Severity breakdown -->
      <div class="grid grid-cols-2 md:grid-cols-3 gap-4 mb-6">
        <div class="card p-4 flex items-center justify-center" style="background: linear-gradient(135deg, #fafbff, #eef2ff);">
          <svg id="detail-ring"></svg>
        </div>
        <div class="grid grid-cols-2 md:grid-cols-3 gap-2" style="grid-column: span 2; align-content: center;">
          ${['Critical','High','Medium','Low','Info'].map(s => `
            <button data-filter-sev="${s}" class="card p-3 text-center cursor-pointer ${filter.severity === s ? 'animate-glow' : ''}" style="${filter.severity === s ? 'border-color: var(--c-brand);' : ''}">
              <div class="text-xs font-semibold" style="text-transform: uppercase; letter-spacing: 0.05em; color: var(--c-text-light);">${s}</div>
              <div style="font-size: 1.75rem; font-weight: 800; font-variant-numeric: tabular-nums; line-height: 1.1; margin-top: 0.25rem; color: ${s==='Critical'?'var(--c-critical)':s==='High'?'var(--c-high)':s==='Medium'?'#ca8a04':s==='Low'?'var(--c-low)':'var(--c-info)'};">${sev[s] || 0}</div>
            </button>
          `).join('')}
        </div>
      </div>

      <!-- Tabs -->
      <div class="tabs">
        <button data-tab="threats" class="tab active">Threats <span class="tab-badge">${total}</span></button>
        <button data-tab="analysis" class="tab">Analysis</button>
        <button data-tab="dfd" class="tab">Data Flow Diagram</button>
        <button data-tab="system" class="tab">System Components</button>
      </div>

      <!-- Threats panel -->
      <div id="tab-threats" class="tab-panel">
        <div class="flex items-center justify-between mb-4 gap-3" style="flex-wrap: wrap;">
          <div class="flex items-center gap-2" style="flex-wrap: wrap;">
            <input id="threat-search" type="text" placeholder="Search threats..." class="input" style="width: 200px;">
            <select id="threat-status-filter" class="select" style="width: auto;">
              <option value="">All statuses</option>
              <option value="open">Open</option>
              <option value="in_progress">In progress</option>
              <option value="mitigated">Mitigated</option>
              <option value="accepted_risk">Accepted</option>
              <option value="false_positive">False positive</option>
            </select>
            ${filter.severity ? `<button id="clear-sev-filter" class="btn btn-sm btn-secondary">Severity: ${filter.severity} ×</button>` : ''}
          </div>
          <div class="flex gap-2">
            <button data-download="markdown" data-tm-id="${tm.id}" class="btn btn-sm btn-secondary">↓ MD</button>
            <button data-download="html" data-tm-id="${tm.id}" class="btn btn-sm btn-secondary">↓ HTML</button>
            <button data-download="pdf" data-tm-id="${tm.id}" class="btn btn-sm btn-secondary">↓ PDF</button>
            <button data-download="csv" data-tm-id="${tm.id}" class="btn btn-sm btn-secondary">↓ CSV</button>
            <button data-download="executive" data-tm-id="${tm.id}" class="btn btn-sm btn-secondary">↓ Exec summary</button>
          </div>
        </div>
        <div id="threat-list" class="flex-col gap-2"></div>
      </div>

      <!-- Analysis panel: risk matrix + attack paths -->
      <div id="tab-analysis" class="tab-panel hidden">
        ${riskMatrixHTML(analysis)}
        ${attackPathsHTML(analysis)}
      </div>

      <!-- DFD panel -->
      <div id="tab-dfd" class="tab-panel hidden">
        <div class="flex items-center justify-between mb-3 gap-2" style="flex-wrap: wrap;">
          <div class="text-xs text-light">🔒 Solid = encrypted · ⚠ Dashed red = unencrypted/cross-boundary · drag components, click to edit</div>
          <button id="btn-save-dfd" class="btn btn-sm btn-primary hidden">Save layout & changes</button>
        </div>
        <div id="dfd-container" class="dfd-container" style="height: 600px;">
          <div class="text-center" style="padding: 3rem 0;">
            <div class="spinner" style="margin: 0 auto;"></div>
            <div class="text-sm text-light mt-3">Loading editor...</div>
          </div>
        </div>
      </div>

      <!-- System panel -->
      <div id="tab-system" class="tab-panel hidden">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <div class="text-xs font-bold text-light mb-2" style="text-transform: uppercase; letter-spacing: 0.08em;">Components (${(tm.system.components || []).length})</div>
            <div class="flex-col gap-1">
              ${(tm.system.components || []).map(c => `
                <div class="card p-3">
                  <div class="font-semibold text-sm">${esc(c.name)}</div>
                  <div class="text-xs text-light">${esc(c.type || 'component')}</div>
                </div>
              `).join('')}
            </div>
          </div>
          <div>
            <div class="text-xs font-bold text-light mb-2" style="text-transform: uppercase; letter-spacing: 0.08em;">Data Flows (${(tm.system.data_flows || []).length})</div>
            <div class="flex-col gap-1">
              ${(tm.system.data_flows || []).map(f => {
                const fromName = (tm.system.components.find(c => c.id === f.from) || {}).name || f.from;
                const toName = (tm.system.components.find(c => c.id === f.to) || {}).name || f.to;
                return `
                  <div class="card p-3">
                    <div class="text-sm font-semibold">
                      ${esc(fromName)} <span class="text-brand">→</span> ${esc(toName)}
                      ${f.encrypted ? '<span style="font-size:0.75rem;">🔒</span>' : '<span style="font-size:0.75rem; color: var(--c-critical);">⚠</span>'}
                    </div>
                    <div class="text-xs text-light">${esc(f.data || '')} · auth: ${esc(f.auth || 'none')}</div>
                  </div>
                `;
              }).join('')}
            </div>
          </div>
        </div>
      </div>

      <div class="mt-6 pt-4 flex justify-between items-center" style="border-top: 1px solid var(--c-border);">
        <div class="text-xs text-light">Created ${(tm.created_at || '').slice(0, 10)}</div>
        <div class="flex gap-2">
          <button id="btn-rerun" class="btn btn-sm btn-secondary" data-tm-id="${tm.id}">↻ Re-run analysis</button>
          ${(tm.owner_id === me.user.id || me.user.role === 'admin') ? `
            <button id="btn-delete-tm" class="btn btn-sm btn-danger" data-tm-id="${tm.id}">Delete</button>
          ` : ''}
        </div>
      </div>
    `;

    document.getElementById('detail-body').innerHTML = body;

    const ring = document.getElementById('detail-ring');
    if (ring) UI.renderRingChart(ring, sev, total, { size: 160 });

    renderThreats();
    wireDetailActions();
  }

  function getFilteredThreats() {
    if (!currentTM || !currentTM.analysis) return [];
    let threats = currentTM.analysis.threats || [];
    if (filter.severity) threats = threats.filter(t => t.severity === filter.severity);
    if (filter.status) {
      threats = threats.filter(t => {
        const s = (currentTM.threat_statuses[t.id] && currentTM.threat_statuses[t.id].status) || 'open';
        return s === filter.status;
      });
    }
    if (filter.search) {
      const q = filter.search.toLowerCase();
      threats = threats.filter(t =>
        (t.title || '').toLowerCase().includes(q) ||
        (t.description || '').toLowerCase().includes(q) ||
        (t.category || '').toLowerCase().includes(q)
      );
    }
    return threats;
  }

  function renderThreats() {
    const list = document.getElementById('threat-list');
    if (!list) return;
    const threats = getFilteredThreats();
    const total = currentTM.analysis.threats.length;
    const statuses = currentTM.threat_statuses || {};

    if (threats.length === 0) {
      list.innerHTML = '<div class="text-center text-sm text-light" style="padding: 2rem;">No threats match filters</div>';
      return;
    }

    list.innerHTML = `
      <div class="text-xs text-light mb-2">Showing ${threats.length} of ${total} threats</div>
      ${threats.slice(0, 100).map((t, i) => {
        const status = (statuses[t.id] && statuses[t.id].status) || 'open';
        const cwe = t.cwe || {};
        const cvss31 = t.cvss31 || {};
        const owasp = (t.references || []).find(r => /A0\d/.test(r.label || ''));
        const dread = t.dread || {};
        const canEdit = (currentTM.owner_id === me.user.id || me.user.role === 'admin');

        return `
          <div data-threat-row data-threat-id="${esc(t.id)}" class="threat-row status-${status}" style="animation: fadeInUp 0.3s ease-out ${Math.min(i, 30)*15}ms backwards">
            <div class="threat-header">
              <div class="sev sev-${t.severity || 'Medium'}">${t.severity || 'Medium'}</div>
              <div style="flex: 1; min-width: 0;">
                <div class="threat-title">${esc(t.title || 'Untitled')}</div>
                <div class="threat-meta">
                  <span class="threat-meta-tag">${esc(t.methodology || '')}</span>
                  <span>${esc(t.category || '')}</span>
                  ${cwe.id ? `<span class="threat-meta-tag threat-meta-tag-cwe">${esc(cwe.id)}</span>` : ''}
                  ${owasp ? `<span class="threat-meta-tag threat-meta-tag-owasp">${esc(owasp.label)}</span>` : ''}
                  ${cvss31.score !== undefined ? `<span class="threat-meta-tag threat-meta-tag-cvss">CVSS ${cvss31.score}</span>` : ''}
                </div>
              </div>
              <div class="flex items-center gap-2">
                ${canEdit ? `
                  <select data-status-select data-threat-id="${esc(t.id)}" class="select" style="font-size: 0.75rem; padding: 0.25rem 0.5rem; width: auto;" onclick="event.stopPropagation()">
                    <option value="open" ${status==='open'?'selected':''}>Open</option>
                    <option value="in_progress" ${status==='in_progress'?'selected':''}>In progress</option>
                    <option value="mitigated" ${status==='mitigated'?'selected':''}>Mitigated</option>
                    <option value="accepted_risk" ${status==='accepted_risk'?'selected':''}>Accepted</option>
                    <option value="false_positive" ${status==='false_positive'?'selected':''}>False positive</option>
                  </select>
                ` : `<span class="status status-${status}">${status.replace('_', ' ')}</span>`}
                <svg class="expand-icon" style="width: 16px; height: 16px; color: var(--c-text-light); transition: transform 0.2s ease;" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7"/></svg>
              </div>
            </div>

            <div class="threat-detail hidden">
              <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                <div class="detail-section" style="margin: 0;">
                  <div class="detail-section-title">Description</div>
                  <p class="text-sm">${esc(t.description || '—')}</p>
                </div>
                <div class="detail-section" style="margin: 0;">
                  <div class="detail-section-title">Location</div>
                  <p class="text-sm">${esc(t.location || '—')}</p>
                </div>
              </div>

              ${t.attack_scenario && t.attack_scenario.length > 0 ? `
                <div class="detail-section">
                  <div class="detail-section-title">⚠ Attack Scenario</div>
                  <div class="flex-col gap-1">
                    ${t.attack_scenario.map((s, i) => `
                      <div class="attack-step">
                        <div class="attack-step-num">${i+1}</div>
                        <div>${esc(s)}</div>
                      </div>
                    `).join('')}
                  </div>
                </div>
              ` : ''}

              ${t.specific_mitigations && t.specific_mitigations.length > 0 ? `
                <div class="detail-section">
                  <div class="detail-section-title" style="color: var(--c-success);">✓ Mitigations</div>
                  ${t.specific_mitigations.map(m => `
                    <div class="mitigation-card">
                      <div class="mitigation-action">${esc(m.action || m)}</div>
                      ${m.detail ? `<div class="mitigation-detail">${esc(m.detail)}</div>` : ''}
                    </div>
                  `).join('')}
                </div>
              ` : (t.mitigations && t.mitigations.length > 0 ? `
                <div class="detail-section">
                  <div class="detail-section-title" style="color: var(--c-success);">✓ Mitigations</div>
                  <ul style="margin: 0; padding-left: 1rem; font-size: 0.875rem;">
                    ${t.mitigations.map(m => `<li>${esc(m)}</li>`).join('')}
                  </ul>
                </div>
              ` : '')}

              <div class="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
                ${cwe.id ? `
                  <div class="metric-box metric-box-cwe">
                    <div class="metric-box-label">CWE</div>
                    <div class="metric-box-value">${esc(cwe.id)}: ${esc(cwe.name || '')}</div>
                    ${cwe.url ? `<a href="${esc(cwe.url)}" target="_blank" class="metric-box-detail" style="color: #7c3aed; text-decoration: none;">View on cwe.mitre.org →</a>` : ''}
                  </div>
                ` : ''}
                ${cvss31.score !== undefined ? `
                  <div class="metric-box metric-box-cvss">
                    <div class="metric-box-label">CVSS 3.1</div>
                    <div class="metric-box-value">${cvss31.score} · ${esc(cvss31.severity || '')}</div>
                    <div class="metric-box-detail">${esc(cvss31.vector || '')}</div>
                  </div>
                ` : ''}
                ${dread.total !== undefined ? `
                  <div class="metric-box metric-box-dread">
                    <div class="metric-box-label">DREAD</div>
                    <div class="metric-box-value">${dread.total}/50</div>
                    <div class="metric-box-detail" style="font-family: inherit; word-break: normal;">D${dread.D_damage} R${dread.R_reproducibility} E${dread.E_exploitability} A${dread.A_affected_users} D${dread.D_discoverability}</div>
                  </div>
                ` : ''}
              </div>

              ${t.references && t.references.length > 0 ? `
                <div class="detail-section">
                  <div class="detail-section-title">References</div>
                  <div class="flex gap-2" style="flex-wrap: wrap;">
                    ${t.references.map(r => `<a href="${esc(r.url || '#')}" target="_blank" class="ref-badge">${esc(r.label || r.url || 'Ref')}</a>`).join('')}
                  </div>
                </div>
              ` : ''}

              <div class="mt-3 flex items-center gap-2" style="padding-top: 0.75rem; border-top: 1px solid var(--c-border); flex-wrap: wrap;">
                <button class="show-history btn btn-sm btn-ghost" data-threat-id="${esc(t.id)}">View status history →</button>
                ${llmConfigured ? `<button class="ai-fix btn btn-sm btn-secondary" data-threat-id="${esc(t.id)}">✨ AI Fix</button>` : ''}
                ${jiraConfigured ? `<button class="create-jira btn btn-sm btn-secondary" data-threat-id="${esc(t.id)}">Create Jira ticket</button>` : ''}
                <div class="status-history mt-2 hidden" style="width:100%;"></div>
                <div class="ai-fix-result mt-2 hidden" style="width:100%;"></div>
              </div>
            </div>
          </div>
        `;
      }).join('')}
      ${threats.length > 100 ? `<p class="text-xs text-center text-light mt-3">Showing first 100 of ${threats.length}. Download a report for the full list.</p>` : ''}
    `;

    list.querySelectorAll('.threat-header').forEach(h => {
      h.addEventListener('click', (e) => {
        if (e.target.closest('select')) return;
        const detail = h.parentElement.querySelector('.threat-detail');
        const icon = h.querySelector('.expand-icon');
        detail.classList.toggle('hidden');
        if (icon) icon.style.transform = detail.classList.contains('hidden') ? '' : 'rotate(180deg)';
      });
    });

    list.querySelectorAll('[data-status-select]').forEach(sel => {
      sel.addEventListener('change', async (e) => {
        e.stopPropagation();
        const threatId = sel.dataset.threatId;
        const newStatus = sel.value;
        const r = await Auth.fetch(`/api/threat-models/${currentTM.id}/threats/${threatId}/status`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: newStatus }),
        });
        if (r.ok) {
          UI.toast(`Status: ${newStatus.replace('_', ' ')}`, 'success', 1500);
          if (!currentTM.threat_statuses) currentTM.threat_statuses = {};
          currentTM.threat_statuses[threatId] = await r.json();
          const row = sel.closest('[data-threat-row]');
          row.className = row.className.replace(/status-\w+/g, '').trim();
          row.classList.add('threat-row', 'status-' + newStatus);
        } else {
          UI.toast('Failed to update', 'error');
        }
      });
    });

    list.querySelectorAll('.show-history').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const threatId = btn.dataset.threatId;
        const container = btn.parentElement.querySelector('.status-history');
        if (!container.classList.contains('hidden')) {
          container.classList.add('hidden');
          btn.textContent = 'View status history →';
          return;
        }
        btn.textContent = 'Loading...';
        const r = await Auth.fetch(`/api/threat-models/${currentTM.id}/threats/${threatId}/history`);
        if (!r.ok) { btn.textContent = 'Failed to load'; return; }
        const history = await r.json();
        if (history.length === 0) {
          container.innerHTML = '<p class="text-xs text-light">No status changes yet</p>';
        } else {
          container.innerHTML = `
            <div class="flex-col gap-1">
              ${history.map(h => {
                const dur = h.duration_in_prev_seconds;
                const durStr = dur === null || dur === undefined ? '' : (
                  dur < 60 ? `${dur}s` :
                  dur < 3600 ? `${Math.round(dur/60)}m` :
                  dur < 86400 ? `${Math.round(dur/3600)}h` :
                  `${Math.round(dur/86400)}d`
                );
                return `
                  <div class="card p-2 flex items-center gap-2" style="font-size: 0.75rem;">
                    <span class="status status-${h.to_status}" style="font-size: 0.625rem;">${h.to_status.replace('_',' ')}</span>
                    ${h.from_status ? `<span class="text-light">from ${h.from_status.replace('_',' ')}</span>` : '<span class="text-light">first set</span>'}
                    ${durStr ? `<span class="text-light">(after ${durStr})</span>` : ''}
                    <span class="text-light">by ${esc(h.changed_by_email || '?')}</span>
                    <span class="text-light" style="margin-left: auto;">${(h.changed_at || '').slice(0,16).replace('T',' ')}</span>
                  </div>
                `;
              }).join('')}
            </div>
          `;
        }
        container.classList.remove('hidden');
        btn.textContent = 'Hide status history ↑';
      });
    });

    list.querySelectorAll('.ai-fix').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const threatId = btn.dataset.threatId;
        const threat = (currentTM.analysis.threats || []).find(x => x.id === threatId);
        if (!threat) return;
        const panel = btn.parentElement.querySelector('.ai-fix-result');
        const original = btn.textContent;
        btn.disabled = true; btn.textContent = 'Generating…';
        try {
          const r = await Auth.fetch('/api/threat/fix', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ threat, system_name: (currentTM.system && currentTM.system.name) || currentTM.name || 'System' }),
          });
          const d = await r.json();
          if (!r.ok) throw new Error(d.detail || 'Fix generation failed');
          const codeBox = (label, code) => `<div style="margin-top:6px;"><div class="text-xs font-semibold text-light" style="text-transform:uppercase;letter-spacing:.05em;">${label}</div><pre style="background:#0f172a;color:#e2e8f0;border-radius:8px;padding:10px 12px;overflow-x:auto;font-size:0.75rem;line-height:1.5;margin:4px 0;"><code>${esc(code || '')}</code></pre></div>`;
          panel.innerHTML = `
            <div class="card p-3" style="background:linear-gradient(135deg,#faf5ff,#eef2ff);border-color:rgba(99,102,241,.25);">
              <div class="flex items-center gap-2 mb-1"><span class="font-semibold text-sm">✨ Suggested fix</span>${d.language ? `<span class="threat-meta-tag" style="font-size:0.625rem;">${esc(d.language)}</span>` : ''}</div>
              ${d.explanation ? `<p class="text-sm text-dim" style="margin:4px 0;">${esc(d.explanation)}</p>` : ''}
              ${d.before ? codeBox('Before', d.before) : ''}
              ${d.after ? codeBox('After', d.after) : ''}
              ${d.diff_summary ? `<p class="text-xs text-light" style="margin-top:6px;">${esc(d.diff_summary)}</p>` : ''}
              <p class="text-xs text-light" style="margin-top:6px;font-style:italic;">AI-generated — review before applying.</p>
            </div>`;
          panel.classList.remove('hidden');
        } catch (err) {
          UI.toast(err.message || 'Could not generate a fix', 'error', 8000);
        } finally {
          btn.disabled = false; btn.textContent = original;
        }
      });
    });

    list.querySelectorAll('.create-jira').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const threatId = btn.dataset.threatId;
        const original = btn.textContent;
        btn.disabled = true; btn.textContent = 'Creating…';
        try {
          const r = await Auth.fetch('/api/create-ticket', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ threat_model_id: currentTM.id, threat_id: threatId }),
          });
          const d = await r.json();
          if (!r.ok) throw new Error(d.detail || 'Ticket creation failed');
          UI.toast(`Jira ticket ${d.key} created`, 'success');
          btn.textContent = `✓ ${d.key}`;
          btn.classList.remove('btn-secondary'); btn.classList.add('btn-ghost');
          if (d.url) { btn.onclick = () => window.open(d.url, '_blank'); btn.disabled = false; btn.title = 'Open in Jira'; }
        } catch (err) {
          UI.toast(err.message || 'Could not create Jira ticket', 'error', 8000);
          btn.disabled = false; btn.textContent = original;
        }
      });
    });
  }

  function wireDetailActions() {
    document.querySelectorAll('.tab').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
        document.getElementById('tab-' + btn.dataset.tab).classList.remove('hidden');
        if (btn.dataset.tab === 'dfd') loadDfd();
      });
    });

    document.querySelectorAll('[data-filter-sev]').forEach(btn => {
      btn.addEventListener('click', () => {
        const sev = btn.dataset.filterSev;
        filter.severity = filter.severity === sev ? null : sev;
        renderDetail();
      });
    });

    const search = document.getElementById('threat-search');
    if (search) search.addEventListener('input', (e) => { filter.search = e.target.value; renderThreats(); });
    const statusFilter = document.getElementById('threat-status-filter');
    if (statusFilter) statusFilter.addEventListener('change', (e) => { filter.status = e.target.value || null; renderThreats(); });
    const clearSev = document.getElementById('clear-sev-filter');
    if (clearSev) clearSev.addEventListener('click', () => { filter.severity = null; renderDetail(); });

    document.querySelectorAll('[data-download]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const fmt = btn.dataset.download;
        const tmId = btn.dataset.tmId;
        const ext = { markdown: 'md', pdf: 'pdf', csv: 'csv', html: 'html', executive: 'html' }[fmt] || 'html';
        const original = btn.innerHTML;
        btn.innerHTML = '<span class="dots-loader"><span></span><span></span><span></span></span>';
        try {
          await UI.downloadFile(`/api/threat-models/${tmId}/report/${fmt}`, `threat_model_${tmId}.${ext}`);
          UI.toast(`${fmt.toUpperCase()} downloaded`, 'success', 1500);
        } catch {}
        btn.innerHTML = original;
      });
    });

    const rerunBtn = document.getElementById('btn-rerun');
    if (rerunBtn) rerunBtn.addEventListener('click', () => runAnalysis(rerunBtn));

    const runBtn = document.getElementById('btn-run-analysis');
    if (runBtn) runBtn.addEventListener('click', () => runAnalysis(runBtn));

    const delBtn = document.getElementById('btn-delete-tm');
    if (delBtn) delBtn.addEventListener('click', () => {
      UI.confirmDialog(`Permanently delete "${currentTM.name}"? This cannot be undone.`, async () => {
        const r = await Auth.fetch(`/api/threat-models/${currentTM.id}`, { method: 'DELETE' });
        if (r.ok) {
          UI.toast('Threat model deleted', 'success');
          UI.hideModal('modal-tm-detail');
          await loadAll();
        } else {
          UI.toast('Delete failed', 'error');
        }
      });
    });
  }

  async function runAnalysis(btn) {
    const original = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="dots-loader"><span></span><span></span><span></span></span> Analyzing...';
    const r = await Auth.fetch(`/api/threat-models/${currentTM.id}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ methodologies: currentTM.methodologies, use_llm: false }),
    });
    if (r.ok) {
      UI.toast('Analysis complete', 'success');
      const r2 = await Auth.fetch('/api/threat-models/' + currentTM.id);
      if (r2.ok) {
        currentTM = await r2.json();
        renderDetail();
      }
    } else {
      UI.toast('Analysis failed', 'error');
      btn.innerHTML = original;
      btn.disabled = false;
    }
  }

  let dfdEditor = null;
  let dfdDirty = false;

  async function loadDfd() {
    const container = document.getElementById('dfd-container');
    if (!container || container.dataset.loaded === '1') return;
    container.dataset.loaded = '1';
    container.innerHTML = '';

    if (!window.DfdEditor) {
      container.innerHTML = '<p style="color: var(--c-critical); font-size: 0.875rem; padding: 2rem;">DFD editor module failed to load. Please refresh the page.</p>';
      return;
    }

    const sourceText = (currentTM.system && currentTM.system._source_text) || currentTM.description || '';
    const canEdit = (currentTM.owner_id === me.user.id || me.user.role === 'admin');

    dfdEditor = window.DfdEditor.mount(container, currentTM.system || {}, {
      readOnly: !canEdit,
      sourceText: sourceText,
      onChange: () => {
        dfdDirty = true;
        const saveBtn = document.getElementById('btn-save-dfd');
        if (saveBtn && canEdit) saveBtn.classList.remove('hidden');
      },
    });

    // Save button handler
    const saveBtn = document.getElementById('btn-save-dfd');
    if (saveBtn && canEdit) {
      saveBtn.addEventListener('click', async () => {
        const updatedSystem = dfdEditor.getSystem();
        // Strip helper-only fields before saving
        delete updatedSystem._source_text;
        delete updatedSystem._boundary_inference_mode;
        const original = saveBtn.innerHTML;
        saveBtn.innerHTML = '<span class="spinner spinner-sm"></span> Saving...';
        saveBtn.disabled = true;
        try {
          const r = await Auth.fetch('/api/threat-models/' + currentTM.id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ system: updatedSystem }),
          });
          if (!r.ok) {
            const data = await r.json().catch(() => ({}));
            throw new Error(UI.formatApiError(data, 'Save failed'));
          }
          currentTM.system = updatedSystem;
          dfdDirty = false;
          saveBtn.classList.add('hidden');
          UI.toast('DFD saved. Re-run analysis to refresh threats.', 'success');
        } catch (e) {
          UI.toast(e.message, 'error');
        } finally {
          saveBtn.innerHTML = original;
          saveBtn.disabled = false;
        }
      });
    }
  }

  // Learn whether Jira is configured so threats can offer a "Create Jira ticket"
  // action. Non-blocking — the dashboard renders regardless.
  fetch('/api/health').then(r => r.json()).then(h => {
    jiraConfigured = !!h.jira_configured;
    llmConfigured = !!h.llm_configured;
  }).catch(() => {});

  loadAll();
})();
