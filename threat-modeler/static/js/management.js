/* Management view: feature rollups, OWASP coverage, drill into TMs (read-only). */
(async function () {
  'use strict';

  const me = await Auth.requireRole(['management', 'admin']);
  if (!me) return;
  const esc = UI.escapeHtml;

  let allFeatures = [];
  let allTMs = [];
  let allUsers = [];
  let overview = [];
  let mgThreats = [];            // flat threat list across all models
  let jiraConfigured = false;    // gates the admin "Create Jira ticket" action
  const isAdmin = (me.user || me).role === 'admin';
  const STALE_DAYS = 30;
  const SEV_ORDER = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
  let tmsSort = { key: 'updated', dir: -1 };   // -1 desc, 1 asc
  let tmsSearch = '';
  let tmsFeatureFilter = null;

  // OWASP top 10 (2021) reference labels
  const OWASP_2021 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
  };

  // Short in-app descriptions so managers don't have to leave for owasp.org
  const OWASP_DESC = {
    "A01:2021": "Users acting outside their intended permissions — missing authorization, IDOR, privilege escalation.",
    "A02:2021": "Failures protecting data in transit or at rest — weak/again absent encryption, exposed secrets.",
    "A03:2021": "Untrusted input interpreted as code or query — SQL, command, LDAP, and cross-site scripting.",
    "A04:2021": "Missing or ineffective security controls by design, before a line of code is written.",
    "A05:2021": "Insecure defaults, verbose errors, unnecessary features, or unpatched configuration.",
    "A06:2021": "Using components with known vulnerabilities or that are unsupported / out of date.",
    "A07:2021": "Weaknesses in confirming identity — credential stuffing, weak sessions, missing MFA.",
    "A08:2021": "Code and infrastructure that don't protect against integrity violations (unsigned updates, insecure deserialization).",
    "A09:2021": "Insufficient logging, detection, and alerting — breaches go unnoticed.",
    "A10:2021": "Server-Side Request Forgery — the server is coerced into making unintended requests.",
  };

  const daysSince = (iso) => {
    if (!iso) return null;
    const t = Date.parse(iso);
    if (isNaN(t)) return null;
    return Math.floor((Date.now() - t) / 86400000);
  };

  function fmtDuration(seconds) {
    if (seconds === null || seconds === undefined) return '—';
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.round(seconds/60)}m`;
    if (seconds < 86400) return `${Math.round(seconds/3600)}h`;
    return `${Math.round(seconds/86400)}d`;
  }

  // Tab switching
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
      document.getElementById('tab-' + btn.dataset.tab).classList.remove('hidden');
    });
  });

  // Honor ?tab= URL param
  const urlTab = new URLSearchParams(window.location.search).get('tab');
  if (urlTab) {
    const btn = document.querySelector(`.tab[data-tab="${urlTab}"]`);
    if (btn) btn.click();
  }

  async function loadAll() {
    const [overviewR, tmsR, featuresR, threatsR, healthR] = await Promise.all([
      Auth.fetch('/api/management/overview'),
      Auth.fetch('/api/threat-models'),
      Auth.fetch('/api/features'),
      Auth.fetch('/api/management/threats'),
      Auth.fetch('/api/health'),
    ]);
    if (!overviewR.ok || !tmsR.ok || !featuresR.ok) {
      UI.toast('Failed to load data', 'error');
      return;
    }
    overview = await overviewR.json();
    allTMs = await tmsR.json();
    allFeatures = await featuresR.json();
    mgThreats = threatsR.ok ? await threatsR.json() : [];
    try { if (healthR.ok) jiraConfigured = !!(await healthR.json()).jira_configured; } catch {}
    try {
      const usersR = await Auth.fetch('/api/users');
      if (usersR.ok) allUsers = await usersR.json();
    } catch {}

    renderMetrics();
    renderRemediation();
    renderAttention();
    renderFeatures();
    renderOwasp();
    renderTMs();
  }

  // Set of tm_ids that have at least one analyzed threat.
  function analyzedTmIds() { return new Set(mgThreats.map(t => t.tm_id)); }

  function renderMetrics() {
    let totalTMs = 0, totalThreats = 0, criticalCount = 0, mitigatedCount = 0;
    overview.forEach(f => {
      totalTMs += f.threat_model_count;
      totalThreats += f.total_threats;
      criticalCount += f.by_severity.Critical || 0;
      mitigatedCount += f.by_status.mitigated || 0;
    });
    UI.animateCount(document.getElementById('m-features'), overview.length);
    UI.animateCount(document.getElementById('m-tms'), totalTMs);
    UI.animateCount(document.getElementById('m-threats'), totalThreats);
    UI.animateCount(document.getElementById('m-critical'), criticalCount);
    UI.animateCount(document.getElementById('m-mitigated'), mitigatedCount);
  }

  // Portfolio remediation progress bar (open → mitigated), from the flat list.
  function renderRemediation() {
    const card = document.getElementById('remediation-card');
    if (!mgThreats.length) { card.classList.add('hidden'); return; }
    const counts = { open: 0, in_progress: 0, mitigated: 0, accepted_risk: 0, false_positive: 0 };
    mgThreats.forEach(t => { counts[t.status] = (counts[t.status] || 0) + 1; });
    const total = mgThreats.length;
    const segs = [
      { k: 'mitigated', label: 'Mitigated', color: 'var(--c-success)' },
      { k: 'in_progress', label: 'In progress', color: 'var(--c-high)' },
      { k: 'accepted_risk', label: 'Accepted', color: 'var(--c-info)' },
      { k: 'false_positive', label: 'False positive', color: 'var(--c-text-light)' },
      { k: 'open', label: 'Open', color: 'var(--c-critical)' },
    ];
    document.getElementById('remediation-bar').innerHTML = segs.filter(s => counts[s.k] > 0).map(s =>
      `<div title="${s.label}: ${counts[s.k]}" style="width:${counts[s.k] / total * 100}%; background:${s.color};"></div>`
    ).join('');
    document.getElementById('remediation-legend').innerHTML = segs.map(s =>
      `<span class="flex items-center gap-1"><span style="width:8px;height:8px;border-radius:2px;display:inline-block;background:${s.color};"></span>${s.label} ${counts[s.k]}</span>`
    ).join('');
    card.classList.remove('hidden');
  }

  // Blind-spots: models not analyzed, stale models, features with no model.
  function renderAttention() {
    const card = document.getElementById('attention-card');
    const body = document.getElementById('attention-body');
    const analyzed = analyzedTmIds();
    const notAnalyzed = allTMs.filter(t => !analyzed.has(t.id));
    const stale = allTMs.filter(t => analyzed.has(t.id) && (daysSince(t.updated_at) || 0) > STALE_DAYS);
    const tmByFeature = {};
    allTMs.forEach(t => { tmByFeature[t.feature_id] = (tmByFeature[t.feature_id] || 0) + 1; });
    const featsNoModel = allFeatures.filter(f => !tmByFeature[f.id]);
    const chip = (n, label, tab) =>
      `<button class="btn btn-sm" data-attn="${tab}" style="background:#fff;border:1px solid #fdba74;color:#9a3412;">${n} ${label}</button>`;
    const chips = [];
    if (notAnalyzed.length) chips.push(chip(notAnalyzed.length, `model${notAnalyzed.length !== 1 ? 's' : ''} not analyzed`, 'threats'));
    if (stale.length) chips.push(chip(stale.length, `stale model${stale.length !== 1 ? 's' : ''} (>${STALE_DAYS}d)`, 'threats'));
    if (featsNoModel.length) chips.push(chip(featsNoModel.length, `feature${featsNoModel.length !== 1 ? 's' : ''} with no threat model`, 'features'));
    if (!chips.length) { card.classList.add('hidden'); return; }
    body.innerHTML = chips.join('');
    body.querySelectorAll('[data-attn]').forEach(b => b.addEventListener('click', () => {
      const tab = document.querySelector(`.tab[data-tab="${b.dataset.attn}"]`);
      if (tab) tab.click();
    }));
    card.classList.remove('hidden');
  }

  function renderFeatures() {
    const grid = document.getElementById('feature-grid');
    if (overview.length === 0) {
      grid.classList.add('hidden');
      document.getElementById('empty-state').classList.remove('hidden');
      return;
    }
    grid.classList.remove('hidden');
    document.getElementById('empty-state').classList.add('hidden');

    grid.innerHTML = overview.map((f, i) => `
      <div class="card card-hover cursor-pointer" data-feature-id="${f.feature_id}" style="padding: 1.25rem;">
        <div class="flex items-start justify-between mb-2">
          <div>
            <h3 style="font-size: 1rem; font-weight: 700; margin: 0 0 2px 0;">${esc(f.feature_name)}</h3>
            <div class="text-xs text-light">${esc(f.release_name)}</div>
          </div>
          <span class="status status-${f.feature_status === 'released' ? 'mitigated' : f.feature_status === 'cancelled' ? 'false_positive' : 'in_progress'}">${esc(f.feature_status)}</span>
        </div>

        <div class="flex justify-center my-3">
          <svg id="ring-${i}"></svg>
        </div>

        <div class="space-y-2 mb-3">
          ${['Critical','High','Medium','Low','Info'].map(sev => {
            const count = f.by_severity[sev] || 0;
            if (count === 0 && f.total_threats > 0) return '';
            const pct = f.total_threats > 0 ? (count / f.total_threats * 100) : 0;
            const colorVar = sev === 'Critical' ? '--c-critical' :
                             sev === 'High' ? '--c-high' :
                             sev === 'Medium' ? '--c-medium' :
                             sev === 'Low' ? '--c-low' : '--c-info';
            return `
              <div class="flex items-center gap-2 text-xs">
                <span class="font-medium" style="width: 60px;">${sev}</span>
                <div class="progress-bar flex-1" style="height: 6px;">
                  <div class="progress-bar-fill" style="background: var(${colorVar}); width: ${pct}%;"></div>
                </div>
                <span class="text-light tabular-nums" style="width: 24px; text-align: right;">${count}</span>
              </div>
            `;
          }).join('')}
        </div>

        ${f.top_critical_titles.length > 0 ? `
          <div class="pt-3" style="border-top: 1px solid var(--c-border);">
            <div class="text-xs font-semibold text-light mb-1" style="text-transform: uppercase; letter-spacing: 0.05em;">⚠ Top critical</div>
            <ul style="margin: 0; padding: 0; list-style: none;">
              ${f.top_critical_titles.slice(0, 3).map(t => `<li class="text-xs" style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; padding: 1px 0;">• ${esc(t)}</li>`).join('')}
            </ul>
          </div>
        ` : ''}

        <div class="flex justify-between text-xs pt-3 mt-3" style="border-top: 1px solid var(--c-border);">
          <div class="text-center flex-1">
            <div class="font-bold" style="color: var(--c-critical);">${f.by_status.open || 0}</div>
            <div class="text-light">Open</div>
          </div>
          <div class="text-center flex-1">
            <div class="font-bold" style="color: var(--c-high);">${f.by_status.in_progress || 0}</div>
            <div class="text-light">In progress</div>
          </div>
          <div class="text-center flex-1">
            <div class="font-bold" style="color: var(--c-success);">${f.by_status.mitigated || 0}</div>
            <div class="text-light">Mitigated</div>
          </div>
        </div>

        ${f.avg_time_to_closure_seconds !== null && f.avg_time_to_closure_seconds !== undefined ? `
          <div class="text-xs text-center mt-2 text-light">
            ⏱ Avg time-to-closure: <strong style="color: var(--c-text);">${fmtDuration(f.avg_time_to_closure_seconds)}</strong>
            <span class="text-light"> · ${f.closures_count} closure${f.closures_count !== 1 ? 's' : ''}</span>
          </div>
        ` : ''}

        <div class="text-xs text-center mt-3 pt-3" style="border-top: 1px solid var(--c-border); color: var(--c-brand); font-weight: 500;">
          ${f.threat_model_count} threat model${f.threat_model_count !== 1 ? 's' : ''} → click to drill in
        </div>
      </div>
    `).join('');

    setTimeout(() => {
      overview.forEach((f, i) => {
        const ring = document.getElementById('ring-' + i);
        if (ring) UI.renderRingChart(ring, f.by_severity, f.total_threats, { size: 140 });
      });
    }, 50);

    document.querySelectorAll('[data-feature-id]').forEach(el => {
      el.addEventListener('click', () => {
        const fid = parseInt(el.dataset.featureId);
        // Switch to All Threat Models tab filtered to this feature
        document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
        const threatsTab = document.querySelector('[data-tab="threats"]');
        threatsTab.classList.add('active');
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
        document.getElementById('tab-threats').classList.remove('hidden');
        tmsFeatureFilter = fid;
        renderTMs();
      });
    });
  }

  function renderOwasp() {
    const grid = document.getElementById('owasp-grid');
    // Aggregate across all features
    const aggregate = {};
    let totalOwasp = 0;
    overview.forEach(f => {
      Object.entries(f.by_owasp || {}).forEach(([cat, n]) => {
        aggregate[cat] = (aggregate[cat] || 0) + n;
        totalOwasp += n;
      });
    });

    if (totalOwasp === 0) {
      grid.innerHTML = `
        <div class="card text-center" style="padding: 3rem; grid-column: 1 / -1;">
          <p class="text-sm text-light">No OWASP-mapped threats yet. Run analysis on threat models to populate this view.</p>
        </div>`;
      return;
    }

    grid.innerHTML = Object.entries(OWASP_2021).map(([code, title]) => {
      const label = `${code} — ${title}`;
      const count = aggregate[label] || 0;
      const pct = totalOwasp > 0 ? (count / totalOwasp * 100).toFixed(1) : 0;
      const sev = count > 10 ? 'critical' : count > 3 ? 'high' : count > 0 ? 'medium' : 'none';
      const colorVar = sev === 'critical' ? '--c-critical' :
                       sev === 'high' ? '--c-high' :
                       sev === 'medium' ? '--c-medium' : '--c-info';
      const bgGradient = sev === 'critical' ? 'linear-gradient(135deg, #fef2f2, #fff)' :
                         sev === 'high' ? 'linear-gradient(135deg, #fff7ed, #fff)' :
                         sev === 'medium' ? 'linear-gradient(135deg, #fefce8, #fff)' :
                         'linear-gradient(135deg, #f8fafc, #fff)';
      const clickable = count > 0;
      return `
        <div class="card ${clickable ? 'card-hover cursor-pointer' : ''}" ${clickable ? `data-owasp-code="${code}"` : ''} style="padding: 1.25rem; background: ${bgGradient};">
          <div class="flex justify-between items-start mb-2">
            <div>
              <div class="text-xs font-bold text-light" style="text-transform: uppercase; letter-spacing: 0.05em;">${code}</div>
              <div style="font-weight: 700; font-size: 0.95rem; margin-top: 2px;">${esc(title)}</div>
            </div>
            <div class="text-right">
              <div style="font-size: 2rem; font-weight: 800; line-height: 1; color: ${count > 0 ? `var(${colorVar})` : 'var(--c-text-light)'}; font-variant-numeric: tabular-nums;">${count}</div>
              <div class="text-xs text-light">${pct}%</div>
            </div>
          </div>
          <p class="text-xs text-light mb-3" style="line-height: 1.4;">${esc(OWASP_DESC[code] || '')}</p>
          <div class="progress-bar" style="height: 6px;">
            <div class="progress-bar-fill" style="background: var(${colorVar}); width: ${pct}%;"></div>
          </div>
          <div class="flex items-center gap-3 mt-2">
            ${clickable ? `<span class="text-xs" style="color: var(--c-brand); font-weight: 500;">View ${count} threat${count !== 1 ? 's' : ''} →</span>` : '<span class="text-xs text-light">No threats detected</span>'}
            <a href="https://owasp.org/Top10/${code.replace(':', '_')}-${title.replace(/ /g, '_')}/" target="_blank" rel="noopener" class="text-xs" style="color: var(--c-text-light); text-decoration: none; margin-left: auto;" onclick="event.stopPropagation()">owasp.org ↗</a>
          </div>
        </div>
      `;
    }).join('');

    grid.querySelectorAll('[data-owasp-code]').forEach(el => {
      el.addEventListener('click', () => openOwasp(el.dataset.owaspCode, OWASP_2021[el.dataset.owaspCode]));
    });
  }

  // Drill into a single OWASP category: list its threats across the portfolio.
  function openOwasp(code, title) {
    UI.showModal('modal-owasp');
    document.getElementById('owasp-title').textContent = `${code} — ${title}`;
    const rows = mgThreats
      .filter(t => (t.owasp || '').startsWith(code))
      .sort((a, b) => (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0));
    document.getElementById('owasp-subtitle').textContent =
      `${rows.length} threat${rows.length !== 1 ? 's' : ''} across the portfolio`;
    const body = document.getElementById('owasp-body');
    if (!rows.length) {
      body.innerHTML = '<p class="text-sm text-light">No threats in this category.</p>';
      return;
    }
    body.innerHTML = `
      <p class="text-sm text-light mb-4">${esc(OWASP_DESC[code] || '')}</p>
      <div class="table-card"><table class="table">
        <thead><tr><th>Severity</th><th>Threat</th><th>Model</th><th>Feature</th><th>Status</th></tr></thead>
        <tbody>
          ${rows.map(t => `
            <tr class="cursor-pointer" data-open-tm="${t.tm_id}">
              <td><span class="sev sev-${t.severity || 'Medium'}">${esc(t.severity || 'Medium')}</span></td>
              <td>${esc(t.title || 'Untitled')}</td>
              <td><strong>${esc(t.tm_name)}</strong></td>
              <td class="text-light">${esc(t.feature || '')}</td>
              <td><span class="status status-${t.status || 'open'}">${(t.status || 'open').replace('_', ' ')}</span></td>
            </tr>`).join('')}
        </tbody>
      </table></div>`;
    body.querySelectorAll('[data-open-tm]').forEach(el => el.addEventListener('click', () => {
      UI.hideModal('modal-owasp');
      openDetail(parseInt(el.dataset.openTm));
    }));
  }

  function tmSeverity(tmId) {
    const s = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    mgThreats.forEach(t => { if (t.tm_id === tmId && s[t.severity] !== undefined) s[t.severity]++; });
    return s;
  }

  function renderTMs() {
    const tbody = document.getElementById('all-tms-tbody');
    const analyzed = analyzedTmIds();
    const featureMap = Object.fromEntries(allFeatures.map(f => [f.id, f]));
    const userMap = Object.fromEntries(allUsers.map(u => [u.id, u]));

    let rows = tmsFeatureFilter ? allTMs.filter(t => t.feature_id === tmsFeatureFilter) : allTMs.slice();
    if (tmsSearch) {
      const q = tmsSearch.toLowerCase();
      rows = rows.filter(t => {
        const fname = (featureMap[t.feature_id] || {}).name || '';
        const owner = (userMap[t.owner_id] || {}).email || '';
        return (t.name || '').toLowerCase().includes(q) ||
               fname.toLowerCase().includes(q) || owner.toLowerCase().includes(q);
      });
    }

    const enrich = rows.map(t => {
      const sev = tmSeverity(t.id);
      return {
        t, sev,
        risk: sev.Critical * 1000 + sev.High * 100 + sev.Medium * 10 + sev.Low,
        feature: (featureMap[t.feature_id] || {}).name || ('#' + t.feature_id),
        owner: (userMap[t.owner_id] || {}).email || ('#' + t.owner_id),
        analyzed: analyzed.has(t.id),
        stale: analyzed.has(t.id) && (daysSince(t.updated_at) || 0) > STALE_DAYS,
      };
    });

    const { key, dir } = tmsSort;
    enrich.sort((a, b) => {
      if (key === 'name') return dir * (a.t.name || '').localeCompare(b.t.name || '');
      if (key === 'feature') return dir * a.feature.localeCompare(b.feature);
      if (key === 'owner') return dir * a.owner.localeCompare(b.owner);
      if (key === 'risk') return dir * (a.risk - b.risk);
      if (key === 'status') {
        const rank = r => (!r.analyzed ? 0 : r.stale ? 1 : 2);
        return dir * (rank(a) - rank(b));
      }
      const av = a.t.updated_at || '', bv = b.t.updated_at || '';
      return dir * (av < bv ? -1 : av > bv ? 1 : 0);
    });

    if (!enrich.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-light" style="padding: 2rem;">No threat models</td></tr>';
    } else {
      const badge = (n, cls) => n > 0
        ? `<span class="sev sev-${cls}" style="padding: 1px 6px; font-size: 0.7rem;">${cls[0]}${n}</span>` : '';
      tbody.innerHTML = enrich.map(r => {
        const riskCell = r.analyzed
          ? `<div class="flex gap-1" style="flex-wrap: wrap;">${badge(r.sev.Critical, 'Critical')}${badge(r.sev.High, 'High')}${badge(r.sev.Medium, 'Medium') || '<span class="text-xs text-light">low risk</span>'}</div>`
          : '<span class="text-xs text-light">—</span>';
        const statusCell = !r.analyzed
          ? '<span class="status status-open">Not analyzed</span>'
          : (r.stale ? '<span class="status status-in_progress">Stale</span>' : '<span class="status status-mitigated">Analyzed</span>');
        return `
          <tr class="cursor-pointer" data-tm-id="${r.t.id}">
            <td><strong>${esc(r.t.name)}</strong></td>
            <td>${esc(r.feature)}</td>
            <td>${riskCell}</td>
            <td>${statusCell}</td>
            <td class="text-light">${esc(r.owner)}</td>
            <td class="text-light text-xs">${(r.t.updated_at || '').slice(0, 10)}${r.stale ? ` · <span style="color: var(--c-high);">${daysSince(r.t.updated_at)}d</span>` : ''}</td>
            <td class="text-right" style="color: var(--c-brand); font-weight: 500;">View →</td>
          </tr>`;
      }).join('');
      tbody.querySelectorAll('[data-tm-id]').forEach(el =>
        el.addEventListener('click', () => openDetail(parseInt(el.dataset.tmId))));
    }

    document.querySelectorAll('#tab-threats th[data-sort]').forEach(th => {
      const base = th.textContent.replace(/\s*[▲▼]$/, '');
      th.textContent = base + (th.dataset.sort === tmsSort.key ? (tmsSort.dir === 1 ? ' ▲' : ' ▼') : '');
    });
  }

  function exportPortfolioCsv() {
    if (!mgThreats.length) { UI.toast('No analyzed threats to export', 'error'); return; }
    const cols = ['Threat Model', 'Feature', 'Threat ID', 'Title', 'Severity', 'Category', 'OWASP', 'CWE', 'Status'];
    const escCsv = (v) => { v = (v == null ? '' : String(v)); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
    const lines = [cols.join(',')];
    mgThreats.forEach(t => lines.push(
      [t.tm_name, t.feature, t.id, t.title, t.severity, t.category, t.owasp || '', t.cwe || '', t.status].map(escCsv).join(',')));
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'portfolio_threats.csv';
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    UI.toast('Portfolio CSV exported', 'success', 1500);
  }

  // ============================================================================
  //  Detail modal — same rich view as user dashboard, but read-only
  // ============================================================================
  let currentTM = null;
  let filter = { severity: null, status: null, search: '' };

  async function openDetail(tmId) {
    UI.showModal('modal-tm-detail');
    document.getElementById('detail-title').textContent = 'Loading...';
    document.getElementById('detail-subtitle').textContent = '';
    document.getElementById('detail-body').innerHTML = `
      <div class="text-center" style="padding: 4rem 0;">
        <div class="dots-loader" style="font-size: 2rem; color: var(--c-brand);"><span></span><span></span><span></span></div>
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
      <div class="card" style="padding:1rem 1.25rem;margin-bottom:1.25rem;background:linear-gradient(135deg,#f8fafc,#fff);">
        <div class="flex items-center justify-between mb-2" style="gap:.5rem;flex-wrap:wrap;">
          <div class="text-xs font-semibold text-light" style="text-transform:uppercase;letter-spacing:.05em;">🧭 Data-flow overview</div>
          <button id="dfo-copy" class="btn btn-sm btn-ghost">Copy</button>
        </div>
        <p class="text-sm" style="line-height:1.5;margin-bottom:.55rem;">${esc(d.narrative || '')}</p>
        <div style="margin-bottom:.35rem;">${statChip('Boundary crossings', st.crossings || 0)}${statChip('Unencrypted flows', st.unencrypted || 0, true)}</div>
        ${group('Entry points', d.entry_points)}
        ${group('Data stores', d.data_stores)}
        ${group('External', d.external_deps)}
        ${risky ? `<div style="margin-top:.5rem;"><span style="${labelS}">Riskiest flows</span><ul class="text-sm" style="margin:.2rem 0 0;padding-left:1.1rem;">${risky}</ul></div>` : ''}
        ${hotspots ? `<div style="margin-top:.5rem;"><span style="${labelS}">Hotspots</span>${hotspots}</div>` : ''}
        ${d.assumptions ? `<div class="text-xs" style="color:#9a3412;margin-top:.5rem;">⚠ ${esc(d.assumptions)}</div>` : ''}
      </div>`;
  }

  function dataFlowOverviewText(d) {
    if (!d) return '';
    const L = [d.narrative || '', ''];
    if ((d.entry_points || []).length) L.push('Entry points: ' + d.entry_points.join(', '));
    if ((d.data_stores || []).length) L.push('Data stores: ' + d.data_stores.join(', '));
    if ((d.external_deps || []).length) L.push('External: ' + d.external_deps.join(', '));
    const st = d.stats || {};
    L.push(`Boundary crossings: ${st.crossings || 0} | Unencrypted flows: ${st.unencrypted || 0}`);
    if ((d.risky_flows || []).length) {
      L.push('', 'Riskiest flows:');
      d.risky_flows.slice(0, 8).forEach(r => L.push(`  - ${r.from} -> ${r.to} (${(r.reasons || []).join('; ')})${r.severity ? ' [' + r.severity + ']' : ''}`));
    }
    if (d.assumptions) L.push('', '! ' + d.assumptions);
    return L.join('\n');
  }

  // Read-only mirror of the dashboard's model-health banner: shows what
  // normalization repaired or flagged so management sees the same honest account.
  function modelIssuesHTML(analysis) {
    const items = (analysis && analysis.model_issues) || [];
    // Only surface the banner for real repairs/problems (error/warning); purely
    // informational notes stay out of the read-only UI (reports still list them).
    if (!items.some(i => i.level === 'error' || i.level === 'warning')) return '';
    const order = { error: 0, warning: 1, info: 2 };
    const meta = {
      error:   { bg: '#fef2f2', bd: '#fecaca', fg: '#b91c1c', icon: '⛔' },
      warning: { bg: '#fffbeb', bd: '#fde68a', fg: '#92400e', icon: '⚠' },
      info:    { bg: '#f8fafc', bd: '#e2e8f0', fg: '#475569', icon: 'ℹ' },
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
      </div>`;
  }

  function assumptionsHTML(analysis) {
    const items = (analysis && analysis.assumptions) || [];
    if (!items.length) return '';
    const rows = items.map(a => `<li style="margin:.2rem 0;line-height:1.45">${esc(a)}</li>`).join('');
    return `
      <details class="card mb-6" style="padding:.7rem 1.1rem;background:#f8fafc;border:1px solid #e2e8f0;">
        <summary style="cursor:pointer;font-size:.72rem;font-weight:600;color:#475569;text-transform:uppercase;letter-spacing:.05em;">
          💡 Assumptions (${items.length}) — what was inferred, not stated
        </summary>
        <ul style="margin:.5rem 0 0;padding-left:1.1rem;font-size:.85rem;color:#334155;">${rows}</ul>
      </details>`;
  }

  function renderDetail() {
    const tm = currentTM;
    const featureName = (allFeatures.find(f => f.id === tm.feature_id) || {}).name || `#${tm.feature_id}`;
    const owner = allUsers.find(u => u.id === tm.owner_id);
    document.getElementById('detail-title').textContent = tm.name;
    document.getElementById('detail-subtitle').textContent =
      `${featureName} · Owner: ${owner ? owner.email : '#' + tm.owner_id} · Updated ${(tm.updated_at || '').slice(0, 10)}`;

    const analysis = tm.analysis;
    if (!analysis) {
      document.getElementById('detail-body').innerHTML = `
        <p class="text-sm text-light mb-4">${esc(tm.description || 'No description')}</p>
        <div class="card text-center" style="padding: 2rem;">
          <p class="text-sm text-light">No analysis run yet on this threat model.</p>
        </div>`;
      return;
    }

    const sev = analysis.summary.by_severity || {};
    const total = analysis.summary.total || 0;

    const body = `
      <p class="text-sm text-light mb-6">${esc(tm.description || 'No description')}</p>

      <div class="grid grid-cols-2 md:grid-cols-3 gap-4 mb-6">
        <div class="card flex items-center justify-center" style="padding: 1rem; background: linear-gradient(135deg, #fafbff, #eef2ff);">
          <svg id="detail-ring"></svg>
        </div>
        <div class="grid grid-cols-2 md:grid-cols-3 gap-2" style="grid-column: span 2; align-content: center;">
          ${['Critical','High','Medium','Low','Info'].map(s => `
            <button data-filter-sev="${s}" class="card cursor-pointer" style="padding: 0.75rem; text-align: center; ${filter.severity === s ? 'border-color: var(--c-brand); box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15);' : ''}">
              <div class="text-xs font-semibold text-light" style="text-transform: uppercase; letter-spacing: 0.05em;">${s}</div>
              <div style="font-size: 1.75rem; font-weight: 800; line-height: 1.1; margin-top: 0.25rem; font-variant-numeric: tabular-nums; color: ${s==='Critical'?'var(--c-critical)':s==='High'?'var(--c-high)':s==='Medium'?'var(--c-medium)':s==='Low'?'var(--c-low)':'var(--c-info)'};">${sev[s] || 0}</div>
            </button>
          `).join('')}
        </div>
      </div>

      ${modelIssuesHTML(analysis)}
      ${assumptionsHTML(analysis)}
      ${dataFlowOverviewHTML(analysis)}

      <div class="tabs" style="margin-bottom: 1rem;">
        <button data-tab="threats" class="tab active">Threats <span class="text-light text-xs">(${total})</span></button>
        <button data-tab="dfd" class="tab">Data Flow Diagram</button>
        <button data-tab="system" class="tab">System Components</button>
      </div>

      <div id="detail-tab-threats" class="detail-tab-panel">
        <div class="flex justify-between items-center mb-4 gap-3" style="flex-wrap: wrap;">
          <div class="flex gap-2 items-center" style="flex-wrap: wrap;">
            <input id="threat-search" type="text" placeholder="Search threats..." class="input" style="font-size: 0.875rem; padding: 0.4rem 0.75rem; width: 12rem;" />
            <select id="threat-status-filter" class="select" style="font-size: 0.875rem; padding: 0.4rem 0.75rem; width: auto;">
              <option value="">All statuses</option>
              <option value="open">Open</option>
              <option value="in_progress">In progress</option>
              <option value="mitigated">Mitigated</option>
              <option value="accepted_risk">Accepted</option>
              <option value="false_positive">False positive</option>
            </select>
            ${filter.severity ? `<button id="clear-sev-filter" class="btn btn-sm" style="background: var(--c-brand); color: white;">Severity: ${filter.severity} ×</button>` : ''}
          </div>
          <div class="flex gap-2">
            <button data-download="markdown" data-tm-id="${tm.id}" class="btn btn-sm btn-ghost">↓ MD</button>
            <button data-download="html" data-tm-id="${tm.id}" class="btn btn-sm btn-ghost">↓ HTML</button>
            <button data-download="pdf" data-tm-id="${tm.id}" class="btn btn-sm btn-ghost">↓ PDF</button>
          </div>
        </div>
        <div id="threat-list"></div>
      </div>

      <div id="detail-tab-dfd" class="detail-tab-panel hidden">
        <div class="card mb-4" style="padding: 1rem;">
          <p class="text-xs text-light mb-2">Numbered badges = flows (red = unencrypted/cross-boundary) · click a badge to inspect</p>
          <div id="dfd-container" style="background: white; border-radius: 6px; padding: 0.75rem; overflow: auto; max-height: 70vh;">
            <div class="text-center" style="padding: 3rem 0;">
              <div class="dots-loader" style="color: var(--c-brand);"><span></span><span></span><span></span></div>
              <div class="text-sm text-light mt-3">Generating diagram...</div>
            </div>
          </div>
        </div>
        ${analysis.system && analysis.system.trust_boundaries && analysis.system.trust_boundaries.length > 0 ? `
          <div class="card" style="padding: 1rem; background: linear-gradient(135deg, #fef3c7, #fffbeb); border-color: #fde68a;">
            <h4 style="font-size: 0.875rem; font-weight: 700; color: #78350f; margin: 0 0 0.5rem 0;">🛡 Trust Boundaries</h4>
            <ul style="margin: 0; padding: 0; list-style: none;">
              ${analysis.system.trust_boundaries.map(b => {
                const components = (b.contains || []).map(cid => {
                  const c = (analysis.system.components || []).find(c => c.id === cid);
                  return c ? c.name : cid;
                });
                return `<li class="text-sm" style="color: #78350f; padding: 2px 0;"><strong>${esc(b.name)}</strong> — contains: ${components.map(esc).join(', ') || '(none)'}</li>`;
              }).join('')}
            </ul>
          </div>
        ` : ''}
      </div>

      <div id="detail-tab-system" class="detail-tab-panel hidden">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <h4 class="text-xs font-semibold text-light mb-2" style="text-transform: uppercase; letter-spacing: 0.05em;">Components (${(tm.system && tm.system.components || []).length})</h4>
            <div class="flex-col gap-1">
              ${(tm.system && tm.system.components || []).map(c => `
                <div class="card" style="padding: 0.6rem 0.75rem;">
                  <div style="font-weight: 600; font-size: 0.875rem;">${esc(c.name)}</div>
                  <div class="text-xs text-light">${esc(c.type || 'component')}</div>
                </div>
              `).join('')}
            </div>
          </div>
          <div>
            <h4 class="text-xs font-semibold text-light mb-2" style="text-transform: uppercase; letter-spacing: 0.05em;">Data Flows (${(tm.system && tm.system.data_flows || []).length})</h4>
            <div class="flex-col gap-1">
              ${(tm.system && tm.system.data_flows || []).map(f => {
                const fromName = (tm.system.components.find(c => c.id === f.from) || {}).name || f.from;
                const toName = (tm.system.components.find(c => c.id === f.to) || {}).name || f.to;
                return `
                  <div class="card" style="padding: 0.6rem 0.75rem;">
                    <div style="font-size: 0.875rem;">${esc(fromName)} <span style="color: var(--c-brand);">→</span> ${esc(toName)} ${f.encrypted ? '🔒' : '<span style="color: var(--c-critical);">⚠</span>'}</div>
                    <div class="text-xs text-light">${esc(f.data || '')} · auth: ${esc(f.auth || 'none')}</div>
                  </div>
                `;
              }).join('')}
            </div>
          </div>
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
      list.innerHTML = '<div class="text-center text-light text-sm" style="padding: 2rem;">No threats match filters</div>';
      return;
    }

    list.innerHTML = `
      <div class="text-xs text-light mb-2">Showing ${threats.length} of ${total} threats</div>
      <div class="flex-col gap-2">
        ${threats.slice(0, 100).map((t, i) => {
          const status = (statuses[t.id] && statuses[t.id].status) || 'open';
          const cwe = t.cwe || {};
          const cvss31 = t.cvss31 || {};
          const owasp = (t.references || []).find(r => /A0\d/.test(r.label || ''));
          const dread = t.dread || {};

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
                  <span class="status status-${status}">${status.replace('_', ' ')}</span>
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
                      ${t.attack_scenario.map((s, idx) => `
                        <div class="attack-step">
                          <div class="attack-step-num">${idx+1}</div>
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

                ${(isAdmin && jiraConfigured) ? `
                  <div class="detail-section" style="border-top: 1px solid var(--c-border); padding-top: 0.75rem;">
                    <button class="create-jira btn btn-sm btn-secondary" data-threat-id="${esc(t.id)}">Create Jira ticket</button>
                  </div>
                ` : ''}
              </div>
            </div>
          `;
        }).join('')}
      </div>
      ${threats.length > 100 ? `<p class="text-xs text-center text-light mt-3">Showing first 100 of ${threats.length}.</p>` : ''}
    `;

    list.querySelectorAll('.threat-header').forEach(h => {
      h.addEventListener('click', (e) => {
        const detail = h.parentElement.querySelector('.threat-detail');
        const icon = h.querySelector('.expand-icon');
        detail.classList.toggle('hidden');
        if (icon) icon.style.transform = detail.classList.contains('hidden') ? '' : 'rotate(180deg)';
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
    document.querySelectorAll('#detail-body .tab').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('#detail-body .tab').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        document.querySelectorAll('.detail-tab-panel').forEach(p => p.classList.add('hidden'));
        document.getElementById('detail-tab-' + btn.dataset.tab).classList.remove('hidden');
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
        const tab = document.querySelector('#detail-body .tab[data-tab="threats"]');
        if (tab) tab.click();
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
    if (search) search.addEventListener('input', (e) => {
      filter.search = e.target.value;
      renderThreats();
    });
    const statusFilter = document.getElementById('threat-status-filter');
    if (statusFilter) statusFilter.addEventListener('change', (e) => {
      filter.status = e.target.value || null;
      renderThreats();
    });

    const clearSev = document.getElementById('clear-sev-filter');
    if (clearSev) clearSev.addEventListener('click', () => {
      filter.severity = null;
      renderDetail();
    });

    document.querySelectorAll('[data-download]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const fmt = btn.dataset.download;
        const tmId = btn.dataset.tmId;
        const ext = fmt === 'markdown' ? 'md' : fmt === 'pdf' ? 'pdf' : 'html';
        const original = btn.innerHTML;
        btn.innerHTML = '<span class="dots-loader"><span></span><span></span><span></span></span>';
        try {
          await UI.downloadFile(`/api/threat-models/${tmId}/report/${fmt}`, `threat_model_${tmId}.${ext}`);
          UI.toast(`${fmt.toUpperCase()} downloaded`, 'success', 1500);
        } catch (e) { /* shown */ }
        btn.innerHTML = original;
      });
    });
  }

  async function loadDfd() {
    const container = document.getElementById('dfd-container');
    if (!container || container.dataset.loaded === '1') return;
    container.dataset.loaded = '1';
    container.innerHTML = '';
    if (!window.DfdEditor) {
      container.innerHTML = '<p class="text-sm" style="color: var(--c-critical);">DFD editor failed to load.</p>';
      return;
    }
    window.DfdEditor.mount(container, currentTM.system || {}, {
      readOnly: true,   // management is read-only
      sourceText: '',
      onChange: function () {},
    });
  }

  // All-models toolbar: search, sortable headers, portfolio export
  document.getElementById('tms-search').addEventListener('input', (e) => {
    tmsSearch = e.target.value;
    renderTMs();
  });
  document.querySelectorAll('#tab-threats th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const k = th.dataset.sort;
      if (tmsSort.key === k) tmsSort.dir *= -1;
      else tmsSort = { key: k, dir: (k === 'updated' || k === 'risk') ? -1 : 1 };
      renderTMs();
    });
  });
  document.getElementById('btn-export-portfolio').addEventListener('click', exportPortfolioCsv);

  document.getElementById('btn-refresh').addEventListener('click', loadAll);
  loadAll();
})();
