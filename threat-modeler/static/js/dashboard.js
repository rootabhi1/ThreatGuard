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
        const sm = tm.analysis.summary || {};
        // Headline counts reflect grounded findings, not generic standard checks.
        threats += (sm.findings != null ? sm.findings : (sm.total || 0));
        const statuses = tm.threat_statuses || {};
        for (const t of tm.analysis.threats || []) {
          if ((t.tier || 'baseline') !== 'evidenced') continue;  // findings only
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
          <div class="flex items-center justify-between mb-2 gap-2">
            <h3 class="font-bold truncate" style="font-size: 1rem;">${esc(tm.name)}</h3>
            ${(tm.owner_id === me.user.id || me.user.role === 'admin') ? `
              <button class="card-delete-tm" data-tm-id="${tm.id}" data-tm-name="${esc(tm.name)}" title="Delete this threat model"
                      style="flex:0 0 auto;border:none;background:none;cursor:pointer;color:var(--c-text-light);padding:2px;line-height:0;border-radius:6px;">
                <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
              </button>` : ''}
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

    container.querySelectorAll('.card[data-tm-id]').forEach(el => {
      el.addEventListener('click', () => openDetail(parseInt(el.dataset.tmId)));
    });
    // Per-card delete — stop the click from opening the detail, confirm first.
    container.querySelectorAll('.card-delete-tm').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const id = parseInt(btn.dataset.tmId);
        const name = btn.dataset.tmName || 'this threat model';
        UI.confirmDialog(`Permanently delete "${name}"? This cannot be undone.`, async () => {
          const r = await Auth.fetch(`/api/threat-models/${id}`, { method: 'DELETE' });
          if (r.ok) { UI.toast('Threat model deleted', 'success'); await loadAll(); }
          else { UI.toast(UI.formatApiError(await r.json().catch(()=>({})), 'Delete failed'), 'error'); }
        });
      });
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

  function setInputMode(mode) {
    const isText = mode === 'text', isStructured = mode === 'structured', isDiagram = mode === 'diagram';
    document.getElementById('template-field').classList.toggle('hidden', !isText);
    document.getElementById('system-text-field').classList.toggle('hidden', !isText);
    document.getElementById('structured-field').classList.toggle('hidden', !isStructured);
    document.getElementById('diagram-field').classList.toggle('hidden', !isDiagram);
    if (!isText) clearTemplate();
  }

  function openNewModal() {
    const form = document.getElementById('form-new-tm');
    if (form) form.reset();
    const stride = document.querySelector('input[name="methodology"][value="stride"]');
    if (stride) stride.checked = true;
    document.getElementById('new-tm-error').classList.add('hidden');
    clearTemplate();
    const textRadio = document.querySelector('input[name="input_mode"][value="text"]');
    if (textRadio) textRadio.checked = true;
    setInputMode('text');
    const legend = document.getElementById('valid-types-legend');
    if (legend) legend.innerHTML = ' <strong>Types:</strong> user, external_entity, webapp, mobile_app, api, auth_service, admin_panel, database, datastore, cache, queue, filesystem, config, payment_service.';
    // Diagram upload is AI-vision only — gate it on a configured provider.
    const diagRadio = document.querySelector('input[name="input_mode"][value="diagram"]');
    const diagCard = diagRadio ? diagRadio.closest('.toggle-card') : null;
    if (diagRadio && diagCard) {
      diagRadio.disabled = !llmConfigured;
      diagCard.style.opacity = llmConfigured ? '' : '0.55';
      diagCard.style.cursor = llmConfigured ? '' : 'not-allowed';
      diagCard.title = llmConfigured ? '' : 'Needs a vision AI provider — configure in Admin → Settings';
      let hint = diagCard.querySelector('.diag-ai-hint');
      if (!llmConfigured && !hint) {
        hint = document.createElement('div');
        hint.className = 'diag-ai-hint toggle-card-sub';
        hint.style.color = 'var(--c-critical)';
        hint.textContent = 'Needs AI provider';
        diagCard.appendChild(hint);
      } else if (llmConfigured && hint) { hint.remove(); }
    }
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
  document.querySelectorAll('input[name="input_mode"]').forEach(r =>
    r.addEventListener('change', () => setInputMode(r.value)));

  // ---- Structured mode: annotated template (download) + one-click example ----
  // '#' and blank lines are ignored by the parser, so this annotated text is both
  // human-readable documentation and directly analyzable if pasted back as-is.
  const STRUCTURED_TEMPLATE = [
    '# ThreatGuard — structured system template',
    '#',
    '# Components — one per line:   Name : type [attr=value, flag]',
    '# Flows      — one per line:   From -> To : protocol, auth, encrypted? [attr=value]',
    '#   protocol : HTTPS, HTTP, TCP, gRPC, WSS, AMQP, ...',
    '#   auth     : session, bearer, mtls, api_key, credentials, none',
    '#   encrypted: encrypted | plaintext',
    '# Lines starting with "#" and blank lines are ignored.',
    '#',
    '# Optional [attributes] set the same security properties as the diagram editor.',
    '#   A bare flag means "yes":   [internet_facing]  ==  [internet_facing=yes]',
    '#   These drive evidenced findings — including the agentic / OWASP-LLM threats.',
    '#   Component attrs: internet_facing, handles_pii/phi/pci, enforces_authorization,',
    '#     rate_limited, encrypted_at_rest, ingests_untrusted_content,',
    '#     prompt_injection_defense, autonomy_level, tool_access, human_in_the_loop,',
    '#     output_validated, sandboxed, memory_scope, content_source_trust, ...',
    '#   Flow attrs: validates_input, provides_integrity, replay_protection,',
    '#     validates_certificates, authorization',
    '#',
    '# Valid types: user, external_entity, webapp, mobile_app, api, auth_service,',
    '#              admin_panel, database, datastore, cache, queue, filesystem, config,',
    '#              payment_service, api_gateway, load_balancer, cdn, waf, ...',
    '#   Agentic:   ai_agent, agent_orchestrator, llm, llm_tool, mcp_server, retriever,',
    '#              agent_memory, knowledge_base, vector_db, guardrail',
    '',
    '# --- Components ---',
    'User               : user',
    'Checkout Service    : api',
    'Orders DB           : database',
    'Event Bus           : queue',
    '# Agentic slice — attributes unlock prompt-injection / excessive-agency / etc.:',
    'Support Agent       : ai_agent [ingests_untrusted_content, prompt_injection_defense=no, autonomy_level=autonomous, tool_access=exec, human_in_the_loop=no, output_validated=no]',
    'Knowledge Base      : retriever [content_source_trust=web_scraped]',
    'Session Memory      : agent_memory [memory_scope=cross_user]',
    '',
    '# --- Flows ---',
    'User -> Checkout Service        : HTTPS, session, encrypted',
    'Checkout Service -> Orders DB    : TCP, credentials, encrypted',
    'Checkout Service -> Event Bus    : AMQP, mtls, encrypted',
    'User -> Support Agent           : HTTPS, session, encrypted',
    'Support Agent -> Knowledge Base  : HTTPS, bearer, encrypted [validates_input=no]',
    'Support Agent -> Session Memory  : TCP, credentials, encrypted',
  ].join('\n');

  const btnStructExample = document.getElementById('btn-structured-example');
  if (btnStructExample) btnStructExample.addEventListener('click', () => {
    const ta = document.querySelector('#form-new-tm textarea[name="structured_text"]');
    if (!ta) return;
    if (ta.value.trim() && !confirm('Replace the current structured input with the example?')) return;
    ta.value = STRUCTURED_TEMPLATE;
    ta.focus();
    const err = document.getElementById('structured-error');
    if (err) { err.classList.add('hidden'); err.textContent = ''; }
  });

  const btnStructTemplate = document.getElementById('btn-structured-template');
  if (btnStructTemplate) btnStructTemplate.addEventListener('click', () => {
    const blob = new Blob([STRUCTURED_TEMPLATE + '\n'], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'threatguard-system-template.txt';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });

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
    const nNew = (d.new_threats || []).length, nRes = (d.resolved_threats || []).length;
    const nChg = (d.changed_severity || []).length, nComp = (d.new_components || []).length + (d.removed_components || []).length;
    const sevDot = s => `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${sevHex(s)};margin-right:6px;"></span>`;
    const stat = (n, label, color) => `
      <div class="card p-3 text-center">
        <div style="font-size:1.5rem;font-weight:800;line-height:1;color:${color};">${n > 0 ? (label==='Resolved'?'▼':'▲') : ''}${n}</div>
        <div class="text-xs text-light mt-1">${label}</div>
      </div>`;
    const rows = (items, render, empty) => items.length
      ? `<div class="flex-col gap-1" style="max-height:240px;overflow-y:auto;">${items.map(render).join('')}</div>`
      : `<p class="text-xs text-light">${empty}</p>`;
    const threatRow = t => `<div class="card p-2 text-sm flex items-center gap-1">${sevDot(t.severity)}<span style="flex:1;">${esc(t.title)}</span><span class="text-light text-xs">${esc(t.component_name||'')}</span></div>`;
    // Compare is meant for the same system across versions. If the two models share
    // no components and no threats, the diff is not a meaningful evolution — warn.
    const ov = d.overlap || {};
    let overlapBanner = '';
    if (ov.unrelated) {
      overlapBanner = `<div class="card p-3 mb-3" style="border-left:4px solid var(--c-critical);background:var(--tone-danger-bg);color:var(--tone-danger-fg);">
        <strong>⚠ These don't look like the same system.</strong> They share no components and no threats,
        so every threat shows as both “new” and “resolved” — this isn't a meaningful diff.
        Compare works best on two versions of the <em>same</em> system (e.g. the same feature across releases).</div>`;
    } else if (ov.common_components !== undefined && (ov.common_components > 0 || ov.common_threats > 0)) {
      overlapBanner = `<div class="text-xs text-light mb-3">Shared basis: ${ov.common_components} common component${ov.common_components===1?'':'s'}, ${ov.common_threats} common threat${ov.common_threats===1?'':'s'}.${ov.same_feature?' Same feature.':''}</div>`;
    }
    out.innerHTML = `
      <div class="flex items-center gap-2 mb-3 text-sm">
        <span class="threat-meta-tag">${esc(d.model_1.name)}</span>
        <span class="text-light">baseline → after</span>
        <span class="threat-meta-tag">${esc(d.model_2.name)}</span>
      </div>
      ${overlapBanner}
      <div class="grid grid-cols-4 gap-2 mb-4">
        ${stat(nNew, 'New', 'var(--c-critical)')}
        ${stat(nRes, 'Resolved', 'var(--c-success)')}
        ${stat(nChg, 'Re-rated', 'var(--ink-medium)')}
        ${stat(nComp, 'Components', 'var(--c-brand)')}
      </div>
      ${nNew+nRes+nChg+nComp === 0 ? '<div class="card p-4 text-center text-sm text-light">No differences — these two analyses are identical.</div>' : `
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div><div class="font-semibold text-sm mb-2" style="color:var(--c-critical);">🆕 New threats</div>${rows(d.new_threats||[], threatRow, 'None added.')}</div>
        <div><div class="font-semibold text-sm mb-2" style="color:var(--c-success);">✅ Resolved threats</div>${rows(d.resolved_threats||[], threatRow, 'None resolved.')}</div>
        <div><div class="font-semibold text-sm mb-2" style="color:var(--ink-medium);">↕ Re-rated severity</div>${rows(d.changed_severity||[], c => `<div class="card p-2 text-sm">${esc(c.threat.title)}: <strong>${esc(c.old)}</strong> → <strong>${esc(c.new)}</strong></div>`, 'No severity changes.')}</div>
        <div><div class="font-semibold text-sm mb-2" style="color:var(--c-brand);">🧩 Component changes</div>${rows([...(d.new_components||[]).map(n=>({t:'+ '+n,c:'var(--c-success)'})), ...(d.removed_components||[]).map(n=>({t:'− '+n,c:'var(--c-critical)'}))], c => `<div class="card p-2 text-sm" style="color:${c.c};">${esc(c.t)}</div>`, 'No component changes.')}</div>
      </div>`}`;
  });

  // Edit threat-model details (rename + description). Registered once.
  document.getElementById('form-edit-tm').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!currentTM) return;
    const form = e.target;
    const errBox = document.getElementById('edit-tm-error');
    const btn = document.getElementById('submit-edit-tm');
    errBox.classList.add('hidden');
    const name = form.name.value.trim();
    if (!name) { errBox.textContent = 'Name is required.'; errBox.classList.remove('hidden'); return; }
    const original = btn.innerHTML;
    btn.disabled = true; btn.innerHTML = '<span class="dots-loader"><span></span><span></span><span></span></span>';
    try {
      const r = await Auth.fetch(`/api/threat-models/${currentTM.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, description: form.description.value }),
      });
      if (!r.ok) throw new Error(UI.formatApiError(await r.json().catch(() => ({})), 'Save failed'));
      currentTM = await r.json();
      document.getElementById('detail-title').textContent = currentTM.name;
      UI.hideModal('modal-edit-tm');
      UI.toast('Details updated', 'success');
      await loadAll();
    } catch (err) {
      errBox.textContent = err.message; errBox.classList.remove('hidden');
    } finally {
      btn.disabled = false; btn.innerHTML = original;
    }
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
      const inputMode = (document.querySelector('input[name="input_mode"]:checked') || {}).value || 'text';

      // ---- Diagram mode: one-shot upload → extract → create → analyze ----
      if (inputMode === 'diagram') {
        const fileInput = document.getElementById('diagram-file');
        if (!fileInput.files || !fileInput.files[0]) throw new Error('Choose an architecture diagram image to upload.');
        if (!featureId) throw new Error('Pick a feature.');
        setProgress('Reading diagram with AI vision…');
        const mfd = new FormData();
        mfd.append('file', fileInput.files[0]);
        mfd.append('feature_id', String(featureId));
        mfd.append('name', fd.get('name') || '');
        mfd.append('description', fd.get('description') || '');
        mfd.append('methodologies', methodologies.join(','));
        mfd.append('analyze', 'true');
        const dResp = await Auth.fetch('/api/threat-models/from-diagram', { method: 'POST', body: mfd });
        if (!dResp.ok) throw new Error((await dResp.json()).detail || 'Diagram analysis failed');
        const d = await dResp.json();
        const tm = d.threat_model;
        const sm = d.analysis ? d.analysis.summary : {};
        const total = (sm.findings != null ? sm.findings : (sm.total || 0));
        UI.hideModal('modal-new-tm');
        const viaVision = d.extraction_method === 'llm_vision';
        UI.toast(`Created "${tm.name}" from ${viaVision ? 'AI vision' : 'the diagram'} — ${total} findings identified`, 'success');
        if (!viaVision)
          UI.toast("AI vision couldn't read the diagram clearly — created an editable starter model; refine it in the Data Flow Diagram tab.", 'info', 8000);
        await loadAll();
        openDetail(tm.id);
        return;
      }

      let system;
      if (inputMode === 'structured') {
        // Exact, deterministic parse of the user's component/flow lines.
        const structError = document.getElementById('structured-error');
        structError.classList.add('hidden');
        setProgress('Parsing structured system...');
        const sResp = await Auth.fetch('/api/extract-structured', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: fd.get('structured_text') }),
        });
        if (!sResp.ok) {
          const msg = (await sResp.json()).detail || 'Could not parse the structured input';
          structError.textContent = msg;
          structError.classList.remove('hidden');
          throw new Error(msg);
        }
        system = await sResp.json();
        // Parsing is lenient: bad lines become line-referenced issues instead of a
        // hard failure. Surface them, but never block — the user still gets a model.
        const structIssues = system.issues || [];
        if ((system.assumptions || []).length) system._assumptions = system.assumptions;
        delete system.assumptions;
        delete system.issues;
        delete system.boundary_inference_mode;
        const structErrors = structIssues.filter(i => i.level === 'error');
        if (structIssues.length) {
          const lvl = structErrors.length ? 'warning' : 'info';
          UI.toast(`Parsed with ${structIssues.length} note${structIssues.length === 1 ? '' : 's'} — see Model health after analysis.`, lvl, 6000);
          if (structErrors.length) {
            structError.innerHTML = structErrors.map(i => esc(i.message)).join('<br>');
            structError.classList.remove('hidden');
          }
        }
        if (!system.name) system.name = fd.get('name');
        system._source_text = fd.get('structured_text');
      } else if (selectedTemplate) {
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
        if ((system.assumptions || []).length) system._assumptions = system.assumptions;
        delete system.assumptions;
        delete system.boundary_inference_mode;
      }

      // If the user left the optional Notes field blank, seed a clean description.
      // For free text the prose itself reads well; for a structured/precise spec the
      // raw "Name : type" lines are NOT a description — summarize the model instead so
      // the card shows something meaningful rather than the spec dump.
      let description = (fd.get('description') || '').trim();
      if (!description) {
        if (inputMode === 'structured') {
          const nc = (system.components || []).length, nf = (system.data_flows || []).length,
                nb = (system.trust_boundaries || []).length;
          const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
          if (nc) description = [plural(nc, 'component'), plural(nf, 'flow')]
            .concat(nb ? [plural(nb, 'trust zone')] : []).join(' · ');
        } else {
          const src = (fd.get('system_text') || (system && system._source_text) || '')
            .split('\n').filter(l => !l.trim().startsWith('#')).join(' ').trim();
          if (src) description = src.length > 160 ? src.slice(0, 157).trimEnd() + '…' : src;
        }
      }

      setProgress('Creating threat model...');
      const createResp = await Auth.fetch('/api/threat-models', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          feature_id: featureId,
          name: fd.get('name'),
          description,
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
      UI.toast(`Created "${tm.name}" — ${analysis.summary.findings != null ? analysis.summary.findings : analysis.summary.total} findings identified`, 'success');
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

  // Plain-language end-to-end data-flow overview (deterministic; from the backend).
  function dataFlowOverviewHTML(analysis) {
    const d = analysis && analysis.dataflow_summary;
    if (!d) return '';
    const st = d.stats || {};
    const chipS = 'display:inline-block;background:#eef2ff;border:1px solid #c7d2fe;color:#3730a3;border-radius:999px;padding:2px 9px;margin:2px 4px 2px 0;font-size:.8rem;cursor:pointer;';
    const labelS = 'display:inline-block;min-width:104px;font-size:.72rem;color:var(--c-text-light);text-transform:uppercase;letter-spacing:.04em;vertical-align:middle;';
    const compChip = (n) => `<button style="${chipS}" data-dfo-comp="${esc(n)}" title="Show threats for ${esc(n)}">${esc(n)}</button>`;
    const group = (label, arr) => (arr && arr.length)
      ? `<div style="margin:3px 0;"><span style="${labelS}">${label}</span>${arr.map(compChip).join('')}</div>` : '';
    const statChip = (label, val, warn) =>
      `<span style="display:inline-block;background:${warn && val > 0 ? '#fef2f2' : '#f1f5f9'};color:${warn && val > 0 ? '#b91c1c' : 'inherit'};border-radius:6px;padding:2px 8px;margin-right:6px;font-size:.8rem;">${label}: <strong>${val}</strong></span>`;
    const risky = (d.risky_flows || []).slice(0, 5).map(r => {
      const hot = (r.severity === 'Critical' || r.severity === 'High');
      return `<li style="margin-bottom:2px;"><strong>${esc(r.from)}</strong> → <strong>${esc(r.to)}</strong> <span class="text-light">— ${esc((r.reasons || []).join('; '))}</span>${r.severity ? ` <span style="${hot ? 'color:var(--c-critical);font-weight:600' : 'color:var(--c-text-light)'}">[${esc(r.severity)}]</span>` : ''}</li>`;
    }).join('');
    const hotspots = (d.hotspots || []).map(h =>
      `${compChip(h.component)}<span class="text-xs text-light" style="margin:0 10px 0 -2px;">${h.critical}C/${h.high}H</span>`).join('');
    return `
      <details class="card mb-6 tg-section" open style="padding:1rem 1.25rem;background:linear-gradient(135deg,#f8fafc,#fff);">
        <summary class="tg-section-summary text-xs font-semibold text-light" style="text-transform:uppercase;letter-spacing:.05em;">🧭 Data-flow overview</summary>
        <div class="tg-section-body">
          <div class="flex justify-end mb-1"><button id="dfo-copy" class="btn btn-sm btn-ghost">Copy</button></div>
          <p class="text-sm" style="line-height:1.5;margin-bottom:.55rem;">${esc(d.narrative || '')}</p>
          <div style="margin-bottom:.35rem;">${statChip('Boundary crossings', st.crossings || 0)}${statChip('Unencrypted flows', st.unencrypted || 0, true)}</div>
          ${group('Entry points', d.entry_points)}
          ${group('Data stores', d.data_stores)}
          ${group('External', d.external_deps)}
          ${risky ? `<div style="margin-top:.5rem;"><span style="${labelS}">Riskiest flows</span><ul class="text-sm" style="margin:.2rem 0 0;padding-left:1.1rem;">${risky}</ul></div>` : ''}
          ${hotspots ? `<div style="margin-top:.5rem;"><span style="${labelS}">Hotspots</span>${hotspots}</div>` : ''}
          ${d.assumptions ? `<div class="text-xs" style="color:#9a3412;margin-top:.5rem;">⚠ ${esc(d.assumptions)}</div>` : ''}
        </div>
      </details>`;
  }

  // Plain-text version of the overview, for the Copy button.
  function dataFlowOverviewText(d) {
    if (!d) return '';
    const L = [];
    L.push(d.narrative || '');
    L.push('');
    if ((d.entry_points || []).length) L.push('Entry points: ' + d.entry_points.join(', '));
    if ((d.data_stores || []).length) L.push('Data stores: ' + d.data_stores.join(', '));
    if ((d.external_deps || []).length) L.push('External: ' + d.external_deps.join(', '));
    const st = d.stats || {};
    L.push(`Boundary crossings: ${st.crossings || 0} | Unencrypted flows: ${st.unencrypted || 0}`);
    if ((d.risky_flows || []).length) {
      L.push(''); L.push('Riskiest flows:');
      d.risky_flows.slice(0, 8).forEach(r => L.push(`  - ${r.from} -> ${r.to} (${(r.reasons || []).join('; ')})${r.severity ? ' [' + r.severity + ']' : ''}`));
    }
    if (d.assumptions) { L.push(''); L.push('! ' + d.assumptions); }
    return L.join('\n');
  }

  // Model-health banner: shows exactly what normalization repaired or flagged
  // (missing/duplicate ids, dangling flow references turned into placeholders,
  // unrecognized types, components outside a boundary). Nothing is ever dropped
  // silently — this is where the user sees the truth about their input.
  function modelIssuesHTML(analysis) {
    const items = (analysis && analysis.model_issues) || [];
    // Only surface the banner when normalization actually repaired or flagged
    // something (error/warning). Purely informational notes stay out of the UI so
    // a well-formed model shows no banner at all; reports still list everything.
    if (!items.some(i => i.level === 'error' || i.level === 'warning')) return '';
    const order = { error: 0, warning: 1, info: 2 };
    const meta = {
      error:   { bg: '#fef2f2', bd: '#fecaca', fg: '#b91c1c', icon: '⛔', word: 'need attention' },
      warning: { bg: '#fffbeb', bd: '#fde68a', fg: '#92400e', icon: '⚠', word: 'auto-resolved' },
      info:    { bg: '#f8fafc', bd: '#e2e8f0', fg: '#475569', icon: 'ℹ', word: 'noted' },
    };
    const counts = { error: 0, warning: 0, info: 0 };
    items.forEach(i => { counts[i.level] = (counts[i.level] || 0) + 1; });
    const sorted = [...items].sort((a, b) => (order[a.level] ?? 3) - (order[b.level] ?? 3));
    const top = counts.error ? meta.error : counts.warning ? meta.warning : meta.info;
    const summary = [
      counts.error ? `${counts.error} need attention` : '',
      counts.warning ? `${counts.warning} auto-resolved` : '',
      counts.info ? `${counts.info} noted` : '',
    ].filter(Boolean).join(' · ');
    const rows = sorted.map(i => {
      const m = meta[i.level] || meta.info;
      return `<li style="display:flex;gap:.5rem;align-items:flex-start;margin:.25rem 0;">
        <span style="color:${m.fg};flex-shrink:0;">${m.icon}</span>
        <span class="text-sm" style="line-height:1.45;">${esc(i.message)}</span></li>`;
    }).join('');
    return `
      <div class="card mb-6" style="padding:.85rem 1.1rem;background:${top.bg};border:1px solid ${top.bd};">
        <div class="text-xs font-semibold" style="color:${top.fg};text-transform:uppercase;letter-spacing:.05em;margin-bottom:.4rem;">
          🩺 Model health — ${esc(summary)}
        </div>
        <ul style="margin:0;padding-left:.1rem;list-style:none;">${rows}</ul>
        ${counts.error ? `<div class="text-xs text-light" style="margin-top:.45rem;">Resolve the flagged items in the Data Flow Diagram tab, then re-run analysis.</div>` : ''}
      </div>`;
  }

  // Assumptions made when the model was seeded from text (inferred flows, defaulted
  // protocol/auth/encryption, auto-added actor). Shown so "stated" and "assumed" are
  // never confused. Collapsible — it's context, not an alarm.
  function assumptionsHTML(analysis) {
    const items = (analysis && analysis.assumptions) || [];
    if (!items.length) return '';
    const rows = items.map(a => `<li style="margin:.2rem 0;line-height:1.45">${esc(a)}</li>`).join('');
    return `
      <details class="card mb-6 tg-section" style="padding:.7rem 1.1rem;background:#f8fafc;border:1px solid #e2e8f0;">
        <summary class="tg-section-summary" style="font-size:.72rem;font-weight:600;color:#475569;text-transform:uppercase;letter-spacing:.05em;">
          💡 Assumptions (${items.length}) — what was inferred, not stated
        </summary>
        <ul style="margin:.5rem 0 0;padding-left:1.1rem;font-size:.85rem;color:#334155;">${rows}</ul>
      </details>`;
  }

  // Readiness checklist: keep the disclosure open across the re-render that each
  // answer triggers, so the user can answer several in a row without it collapsing.
  let readinessOpen = false;

  function readinessHTML(analysis) {
    const rd = analysis && analysis.readiness;
    if (!rd || !rd.applicable) return '';
    const canEdit = (currentTM.owner_id === me.user.id || me.user.role === 'admin');
    const pct = rd.score;
    const barColor = pct >= 75 ? 'var(--c-success)' : pct >= 40 ? 'var(--ink-medium)' : 'var(--c-high)';
    const openN = rd.open_count;

    const answerCtl = (q) => {
      if (!canEdit) return '';
      const d = `data-rq-answer data-scope="${q.scope}" data-target="${esc(q.target_id)}" data-attr="${esc(q.attr)}"`;
      if (q.kind === 'yn') {
        return `<span class="rq-yn"><button class="rq-btn" ${d} data-value="yes">Yes</button><button class="rq-btn" ${d} data-value="no">No</button></span>`;
      }
      return `<select class="rq-select" ${d}>${q.options.map(o => `<option value="${esc(o)}">${o === '' ? '— pick —' : esc(o)}</option>`).join('')}</select>`;
    };

    const groups = {};
    (rd.questions || []).forEach(q => {
      (groups[q.target_id] = groups[q.target_id] || { name: q.target_name, type: q.target_type, scope: q.scope, items: [] }).items.push(q);
    });
    const groupHTML = Object.values(groups).map(g => `
      <div class="rq-group">
        <div class="rq-group-head">${g.scope === 'flow' ? '⇄' : '▪'} ${esc(g.name)} <span class="tg-muted">${esc(g.type)}</span></div>
        ${g.items.map(q => `<div class="rq-row"><span class="rq-label">${esc(q.label)}</span>${answerCtl(q)}</div>`).join('')}
      </div>`).join('');

    return `
      <div class="card mb-6 rq-card">
        <div class="rq-meter-head">
          <div><div class="rq-title">Model completeness</div>
            <div class="rq-sub">${rd.answered} of ${rd.applicable} security questions answered${openN ? ` · ${openN} open` : ' · complete'}</div></div>
          <div class="rq-score" style="color:${barColor};">${pct}%</div>
        </div>
        <div class="rq-track"><div class="rq-fill" style="width:${pct}%;background:${barColor};"></div></div>
        ${openN ? `
        <details class="tg-disclosure rq-disclosure" ${readinessOpen ? 'open' : ''}>
          <summary>Answer ${openN} question${openN > 1 ? 's' : ''} to sharpen generic checks into findings — or clear them</summary>
          <div class="tg-disclosure-body rq-list">${groupHTML}</div>
        </details>` : `<div class="rq-done">✓ Every applicable security question is answered — findings reflect your model.</div>`}
      </div>`;
  }

  async function answerReadiness(scope, targetId, attr, value) {
    if (!value) return;
    const sys = JSON.parse(JSON.stringify(currentTM.system || {}));
    const list = scope === 'flow' ? (sys.data_flows || []) : (sys.components || []);
    const t = list.find(x => x.id === targetId);
    if (!t) return;
    t[attr] = value;
    try {
      const put = await Auth.fetch('/api/threat-models/' + currentTM.id, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ system: sys }),
      });
      if (!put.ok) throw new Error('Save failed');
      const an = await Auth.fetch('/api/threat-models/' + currentTM.id + '/analyze', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ methodologies: currentTM.methodologies, use_llm: false }),
      });
      if (!an.ok) throw new Error('Analysis failed');
      const r2 = await Auth.fetch('/api/threat-models/' + currentTM.id);
      if (r2.ok) { currentTM = await r2.json(); renderDetail(); }
    } catch (e) {
      UI.toast(e.message || 'Failed to save answer', 'error');
    }
  }

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

    const total = analysis.summary.total || 0;
    // Grounded findings (proven by the model) drive the headline numbers; generic
    // "standard checks" (baseline) are shown separately so they don't read as false
    // positives. Fall back to the old all-tiers counts for pre-split stored analyses.
    const sev = analysis.summary.findings_by_severity || analysis.summary.by_severity || {};
    const findings = analysis.summary.findings != null ? analysis.summary.findings : total;
    const stdChecks = analysis.summary.standard_checks || 0;

    const body = `
      <p class="text-sm text-dim mb-6">${esc(tm.description || 'No description')}</p>

      <!-- Severity breakdown (grounded findings) -->
      <div class="flex items-baseline gap-3 mb-2" style="flex-wrap:wrap;">
        <span class="text-xs font-semibold" style="text-transform:uppercase;letter-spacing:.06em;color:var(--c-text-light);">Findings — proven by your model</span>
        ${stdChecks ? `<span class="text-xs text-light">·&nbsp; ${stdChecks} standard check${stdChecks>1?'s':''} to review (not counted)</span>` : ''}
      </div>
      <div class="grid grid-cols-2 md:grid-cols-3 gap-4 mb-6">
        <div class="card p-4 flex items-center justify-center" style="background: linear-gradient(135deg, #fafbff, #eef2ff);">
          <svg id="detail-ring"></svg>
        </div>
        <div class="grid grid-cols-2 md:grid-cols-3 gap-2" style="grid-column: span 2; align-content: center;">
          ${['Critical','High','Medium','Low','Info'].map(s => `
            <button data-filter-sev="${s}" class="card p-3 text-center cursor-pointer ${filter.severity === s ? 'animate-glow' : ''}" style="${filter.severity === s ? 'border-color: var(--c-brand);' : ''}">
              <div class="text-xs font-semibold" style="text-transform: uppercase; letter-spacing: 0.05em; color: var(--c-text-light);">${s}</div>
              <div style="font-size: 1.75rem; font-weight: 800; font-variant-numeric: tabular-nums; line-height: 1.1; margin-top: 0.25rem; color: ${s==='Critical'?'var(--c-critical)':s==='High'?'var(--c-high)':s==='Medium'?'var(--ink-medium)':s==='Low'?'var(--c-low)':'var(--c-info)'};">${sev[s] || 0}</div>
            </button>
          `).join('')}
        </div>
      </div>

      ${readinessHTML(analysis)}
      ${modelIssuesHTML(analysis)}
      ${assumptionsHTML(analysis)}
      ${dataFlowOverviewHTML(analysis)}

      <!-- Tabs -->
      <div class="tabs">
        <button data-tab="threats" class="tab active">Threats <span class="tab-badge">${findings}</span></button>
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
          <div class="text-xs text-light">Numbered badges = flows (red = unencrypted/cross-boundary) · click a badge to inspect · drag components to arrange</div>
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
          ${(tm.owner_id === me.user.id || me.user.role === 'admin') ? `
            <button id="btn-edit-tm" class="btn btn-sm btn-secondary" data-tm-id="${tm.id}">✎ Edit details</button>` : ''}
          <button id="btn-rerun" class="btn btn-sm btn-secondary" data-tm-id="${tm.id}">↻ Re-run analysis</button>
          ${(tm.owner_id === me.user.id || me.user.role === 'admin') ? `
            <button id="btn-delete-tm" class="btn btn-sm btn-danger" data-tm-id="${tm.id}">Delete</button>
          ` : ''}
        </div>
      </div>
    `;

    document.getElementById('detail-body').innerHTML = body;

    const ring = document.getElementById('detail-ring');
    if (ring) UI.renderRingChart(ring, sev, findings, { size: 160 });

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
        (t.category || '').toLowerCase().includes(q) ||
        (t.component_name || '').toLowerCase().includes(q)
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
      list.innerHTML = `<div class="empty-state" style="padding:2.5rem 1rem;">
        <div class="empty-state-art">🔍</div>
        <div class="empty-state-title">No threats match your filters</div>
        <div class="empty-state-desc">Try clearing the severity or status filter, or the search box.</div>
      </div>`;
      return;
    }

    // Plain-language meaning of each methodology category, so a card explains
    // itself instead of assuming the reader knows STRIDE / LINDDUN / PASTA.
    const CATEGORY_DESC = {
      // STRIDE
      'spoofing': 'Pretending to be a user or system you are not, to gain trust or access.',
      'tampering': 'Altering data or code in transit or at rest so it no longer behaves as intended.',
      'repudiation': 'Performing an action that cannot later be proven — missing or forgeable audit trail.',
      'information disclosure': 'Exposing data to someone not authorised to see it.',
      'denial of service': 'Making a system slow or unavailable to legitimate users.',
      'elevation of privilege': 'Gaining rights beyond what was granted — the classic path to full compromise.',
      // LINDDUN (privacy)
      'linkability': 'Being able to tell that two records or actions relate to the same person.',
      'identifiability': 'Being able to single out the individual behind the data.',
      'non-repudiation': 'A person being unable to plausibly deny an action (a privacy harm here, not a security one).',
      'detectability': 'Being able to tell that a record or item exists at all.',
      'disclosure of information': 'Personal data exposed to a party not authorised to see it.',
      'unawareness': 'People not knowing, or not being able to control, how their data is used.',
      'non-compliance': 'Processing that breaks a privacy obligation (consent, purpose, retention, residency).',
    };
    const catDesc = (t) => {
      const c = String(t.category || '').toLowerCase().trim();
      if (CATEGORY_DESC[c]) return CATEGORY_DESC[c];
      if (c.startsWith('stage')) return 'A PASTA stage — attack simulation & risk analysis for this part of the system.';
      return '';
    };

    // DREAD is derived from independent model signals (not five copies of severity),
    // so show what each axis measures — that makes the score auditable, not magic.
    const DREAD_AXES = [
      ['D_damage', 'Damage', 'how bad the impact is if exploited'],
      ['R_reproducibility', 'Reproducibility', 'how reliably an attacker can repeat it'],
      ['E_exploitability', 'Exploitability', 'how little stands between the attacker and the exploit'],
      ['A_affected_users', 'Affected users', 'the blast radius / how many are hit'],
      ['D_discoverability', 'Discoverability', 'how easily the weakness is found'],
    ];
    const dreadBar = (n) => {
      const pct = Math.round((Math.max(1, Math.min(10, n)) / 10) * 100);
      const col = n >= 8 ? 'var(--c-critical)' : n >= 6 ? 'var(--c-high)' : n >= 4 ? 'var(--ink-medium)' : 'var(--c-low)';
      return `<span style="display:inline-block;width:56px;height:6px;border-radius:3px;background:var(--c-border);vertical-align:middle;overflow:hidden;">
        <span style="display:block;width:${pct}%;height:100%;background:${col};"></span></span>`;
    };

    // Framework badges use the shared token-driven pill (.tg-badge--framework +
    // data-fw) so their colours match the reports and coverage strip.
    const frameworkBadges = (t) => {
      if (!t.frameworks || !t.frameworks.length) return '';
      return `<div class="detail-section">
        <div class="detail-section-title">Framework mapping</div>
        <div class="flex gap-2" style="flex-wrap:wrap;">
          ${t.frameworks.map(fr => `<a href="${esc(fr.url || '#')}" target="_blank" title="${esc(fr.label)}"
              class="tg-badge tg-badge--framework" data-fw="${esc(fr.framework)}" style="text-decoration:none;">
              <span class="tg-fw-key">${esc(fr.framework)}</span>${esc(fr.id)}</a>`).join('')}
        </div></div>`;
    };
    // Disclosed (not dropped): generic threats a positively-answered control negated.
    const suppressed = currentTM.analysis.suppressed_threats || [];
    const suppressedBanner = suppressed.length ? `
      <details class="tg-disclosure" style="margin-bottom:.6rem;">
        <summary>${suppressed.length} generic threat${suppressed.length>1?'s':''} suppressed by controls you answered</summary>
        <div class="tg-disclosure-body" style="display:flex;flex-direction:column;gap:.35rem;">
          ${suppressed.map(t => `<div class="text-xs"><span class="tg-strike">${esc(t.title)}</span><span class="tg-muted"> — ${esc(t.suppression_reason || '')}</span></div>`).join('')}
        </div>
      </details>` : '';

    const cardHTML = (t, i) => {
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
                  <span title="${esc(catDesc(t))}" style="${catDesc(t) ? 'border-bottom:1px dotted var(--c-text-light);cursor:help;' : ''}">${esc(t.category || '')}</span>
                  ${t.tier === 'evidenced' ? `<span class="tg-badge tg-badge--finding" title="The model proves this threat's precondition">finding</span>` : (t.tier === 'baseline' ? `<span class="tg-badge tg-badge--standard" title="Generic type-template — no model evidence proves it applies here; not counted as a finding">standard check</span>` : '')}
                  ${t.severity_original ? `<span class="tg-badge tg-badge--calibrated" title="${esc(t.severity_rationale || '')}">${esc(t.severity_original)}→${esc(t.severity)}</span>` : ''}
                  ${cwe.id ? `<span class="threat-meta-tag threat-meta-tag-cwe">${esc(cwe.id)}</span>` : ''}
                  ${owasp ? `<span class="threat-meta-tag threat-meta-tag-owasp">${esc(owasp.label)}</span>` : ''}
                  ${cvss31.score !== undefined ? `<span class="threat-meta-tag threat-meta-tag-cvss" title="Estimated from the threat class — refine against a concrete finding">CVSS ${cvss31.score}~</span>` : ''}
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

              ${catDesc(t) ? `
                <div class="detail-section" style="margin: 0 0 1rem;">
                  <div class="detail-section-title">${esc(t.methodology || '')} · ${esc(t.category || '')}</div>
                  <p class="text-sm text-dim">${esc(catDesc(t))}</p>
                </div>
              ` : ''}

              ${t.evidence ? `
                <div class="detail-section tg-evidence">
                  <div class="detail-section-title">Why this fired</div>
                  <p class="text-sm text-dim">${esc(t.evidence)}${t.severity_original ? ` <span class="tg-evidence-cal">· severity ${esc(t.severity_rationale || '')}</span>` : ''}</p>
                </div>
              ` : ''}

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
                ${dread.total !== undefined ? `
                  <div class="metric-box metric-box-dread">
                    <div class="metric-box-label">DREAD · primary risk score</div>
                    <div class="metric-box-value">${dread.total}/50${dread.tier ? ` · ${esc(dread.tier)}` : ''}</div>
                    <div class="metric-box-detail" style="font-family: inherit; word-break: normal;">derived from your model — see breakdown below</div>
                  </div>
                ` : ''}
                ${cvss31.score !== undefined ? `
                  <div class="metric-box metric-box-cvss">
                    <div class="metric-box-label" title="Estimated from the threat class, not a measured CVE. Refine against a concrete finding.">CVSS 3.1 · estimated</div>
                    <div class="metric-box-value">${cvss31.score} · ${esc(cvss31.severity || '')}</div>
                    <div class="metric-box-detail">${esc(cvss31.vector || '')}</div>
                  </div>
                ` : ''}
              </div>

              ${dread.total !== undefined ? `
                <div class="detail-section" style="margin: 0 0 1rem;">
                  <div class="detail-section-title">Why this DREAD score (${dread.total}/50)</div>
                  <div style="display:grid;grid-template-columns:auto 116px 1fr;gap:6px 14px;align-items:center;font-size:0.8125rem;">
                    ${DREAD_AXES.map(([k, label, meaning]) => `
                      <span style="font-weight:600;white-space:nowrap;">${label}</span>
                      <span style="white-space:nowrap;">${dreadBar(dread[k] || 0)} <span style="font-variant-numeric:tabular-nums;">${dread[k] || 0}/10</span></span>
                      <span class="text-dim">${meaning}</span>
                    `).join('')}
                  </div>
                  <p class="text-xs text-light" style="margin-top:.5rem;">DREAD is the primary risk ranking at threat-model stage; CVSS above is an estimate from the threat class.</p>
                </div>
              ` : ''}

              ${frameworkBadges(t)}
              ${(() => {
                const fwLabels = new Set((t.frameworks || []).map(f => f.label));
                const otherRefs = (t.references || []).filter(r => !fwLabels.has(r.label));
                if (!otherRefs.length) return '';
                return `
                <div class="detail-section">
                  <div class="detail-section-title">References</div>
                  <div class="flex gap-2" style="flex-wrap: wrap;">
                    ${otherRefs.map(r => `<a href="${esc(r.url || '#')}" target="_blank" class="ref-badge">${esc(r.label || r.url || 'Ref')}</a>`).join('')}
                  </div>
                </div>`;
              })()}

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
    };

    // Split grounded findings (proven by the model) from generic "standard checks"
    // (baseline type-templates). Findings lead; standard checks live in a collapsed,
    // muted section and are NOT counted as findings — so generic items stop reading
    // as false positives. Nothing is dropped: every check is one click away.
    const findings = threats.filter(t => (t.tier || 'baseline') === 'evidenced');
    const checks = threats.filter(t => (t.tier || 'baseline') !== 'evidenced');
    const checksSection = checks.length ? `
      <details class="tg-disclosure" style="margin-top:.85rem;">
        <summary>${checks.length} standard check${checks.length>1?'s':''} — generic risks for these component types your model doesn't yet confirm or rule out <span class="tg-muted">(not counted as findings)</span></summary>
        <div class="tg-disclosure-body" style="opacity:.92;">${checks.slice(0, 100).map(cardHTML).join('')}</div>
        ${checks.length > 100 ? `<p class="text-xs text-center text-light mt-2">Showing first 100 of ${checks.length} standard checks.</p>` : ''}
      </details>` : '';

    list.innerHTML = `
      <div class="text-xs text-light mb-2">${findings.length} finding${findings.length!==1?'s':''}${checks.length?` · ${checks.length} standard check${checks.length>1?'s':''}`:''}${suppressed.length ? ` · ${suppressed.length} suppressed` : ''}</div>
      ${suppressedBanner}
      ${findings.slice(0, 100).map(cardHTML).join('')}
      ${findings.length === 0 ? `<div class="empty-state" style="padding:2rem 1rem;">
        <div class="empty-state-art">✓</div>
        <div class="empty-state-title">No grounded findings here</div>
        <div class="empty-state-desc">Your model didn't prove any threats for this filter. Review the standard checks below, or answer more security properties on components to sharpen the model.</div>
      </div>` : ''}
      ${findings.length > 100 ? `<p class="text-xs text-center text-light mt-3">Showing first 100 of ${findings.length} findings. Download a report for the full list.</p>` : ''}
      ${checksSection}
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

    // Data-flow overview: click a component → filter Threats to it; Copy button.
    document.querySelectorAll('[data-dfo-comp]').forEach(btn => {
      btn.addEventListener('click', () => {
        filter.search = btn.dataset.dfoComp;
        document.querySelector('.tab[data-tab="threats"]').click();
        const s = document.getElementById('threat-search');
        if (s) s.value = filter.search;
        renderThreats();
      });
    });
    const dfoCopy = document.getElementById('dfo-copy');
    if (dfoCopy) dfoCopy.addEventListener('click', async () => {
      const txt = dataFlowOverviewText(currentTM.analysis && currentTM.analysis.dataflow_summary);
      try { await navigator.clipboard.writeText(txt); UI.toast('Overview copied', 'success', 1500); }
      catch { UI.toast('Copy failed', 'error'); }
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

    // Readiness checklist — answering a question saves the attribute + re-analyses.
    const rqDisc = document.querySelector('.rq-disclosure');
    if (rqDisc) rqDisc.addEventListener('toggle', () => { readinessOpen = rqDisc.open; });
    document.querySelectorAll('[data-rq-answer]').forEach(el => {
      const isSelect = el.tagName === 'SELECT';
      el.addEventListener(isSelect ? 'change' : 'click', () => {
        const value = isSelect ? el.value : el.dataset.value;
        if (!value) return;
        readinessOpen = true;
        el.closest('.rq-card')?.classList.add('rq-busy');
        answerReadiness(el.dataset.scope, el.dataset.target, el.dataset.attr, value);
      });
    });

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

    const editBtn = document.getElementById('btn-edit-tm');
    if (editBtn) editBtn.addEventListener('click', () => {
      const form = document.getElementById('form-edit-tm');
      form.name.value = currentTM.name || '';
      form.description.value = currentTM.description || '';
      document.getElementById('edit-tm-error').classList.add('hidden');
      UI.showModal('modal-edit-tm');
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

    // When the saved model defines no trust boundaries, analysis infers them (and the
    // cross-boundary threats are based on those inferred zones). Seed the editor with
    // the same inferred boundaries so the diagram matches the threats instead of
    // showing a flat, zone-less system that contradicts the findings.
    const baseSys = currentTM.system || {};
    let sysForDfd = baseSys;
    if (!((baseSys.trust_boundaries || []).length)) {
      const inferred = ((currentTM.analysis && currentTM.analysis.system) || {}).trust_boundaries || [];
      if (inferred.length) sysForDfd = { ...baseSys, trust_boundaries: inferred };
    }

    dfdEditor = window.DfdEditor.mount(container, sysForDfd, {
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
