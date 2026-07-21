/* ====================================================================
   DFD Editor — interactive Data Flow Diagram editor
   ====================================================================
   Renders an editable SVG diagram of a system's components, data flows,
   and trust boundaries. Provides:
     - drag-to-reposition (with snap-to-grid)
     - inline edit (rename, change type, toggle encryption)
     - add / remove components / flows / boundaries
     - drag between trust boundaries
     - toggle visual layers
     - save layout positions
     - re-infer trust boundaries (heuristic or LLM)

   Public API: window.DfdEditor.mount(container, system, options)
     options: {
       readOnly: bool,
       sourceText: string,        // for LLM re-inference
       onChange: function(system) // called whenever the system changes
     }
   Returns an instance with: getSystem(), destroy()
   ==================================================================== */
(function () {
  'use strict';

  const GRID = 20;
  const CANVAS_W = 1200;
  const CANVAS_H = 700;
  const COMP_W = 120;
  const COMP_H = 64;
  const BOUNDARY_PADDING = 24;

  // Component type → emoji + accent color
  const TYPE_VISUALS = {
    user:            { icon: '👤', color: '#6366f1' },
    external_entity: { icon: '🌐', color: '#06b6d4' },
    webapp:          { icon: '💻', color: '#3b82f6' },
    mobile_app:      { icon: '📱', color: '#8b5cf6' },
    api:             { icon: '⚙', color: '#10b981' },
    api_gateway:     { icon: '🚪', color: '#10b981' },
    auth_service:    { icon: '🔐', color: '#f59e0b' },
    admin_panel:     { icon: '🛠', color: '#ef4444' },
    database:        { icon: '🗄', color: '#0891b2' },
    datastore:       { icon: '💾', color: '#0891b2' },
    cache:           { icon: '⚡', color: '#dc2626' },
    queue:           { icon: '📨', color: '#9333ea' },
    filesystem:      { icon: '📁', color: '#64748b' },
    payment_service: { icon: '💳', color: '#16a34a' },
    load_balancer:   { icon: '⚖', color: '#0ea5e9' },
    service:         { icon: '⚙', color: '#10b981' },
    worker:          { icon: '⚙', color: '#10b981' },
    cdn:             { icon: '🌐', color: '#06b6d4' },
    object_storage:  { icon: '📦', color: '#0891b2' },
    vector_db:       { icon: '🧠', color: '#a855f7' },
    // Cloud / infrastructure
    serverless:          { icon: '☁', color: '#f59e0b' },
    container:           { icon: '🐳', color: '#0ea5e9' },
    kubernetes:          { icon: '☸', color: '#3b82f6' },
    waf:                 { icon: '🧱', color: '#ef4444' },
    secrets_manager:     { icon: '🔑', color: '#f59e0b' },
    iam:                 { icon: '🪪', color: '#f59e0b' },
    vpc:                 { icon: '🕸', color: '#64748b' },
    data_warehouse:      { icon: '🏬', color: '#0891b2' },
    monitoring:          { icon: '📈', color: '#16a34a' },
    notification_service:{ icon: '🔔', color: '#9333ea' },
    // Second wave — modern services & infra
    llm:                 { icon: '🤖', color: '#a855f7' },
    ai_agent:            { icon: '🦾', color: '#7c3aed' },
    agent_orchestrator:  { icon: '🎛', color: '#7c3aed' },
    llm_tool:            { icon: '🔧', color: '#7c3aed' },
    mcp_server:          { icon: '🔌', color: '#7c3aed' },
    agent_memory:        { icon: '💭', color: '#7c3aed' },
    retriever:           { icon: '🧲', color: '#7c3aed' },
    guardrail:           { icon: '🚧', color: '#7c3aed' },
    knowledge_base:      { icon: '📚', color: '#7c3aed' },
    identity_provider:   { icon: '🆔', color: '#f59e0b' },
    email_service:       { icon: '✉️', color: '#0ea5e9' },
    sms_gateway:         { icon: '📲', color: '#0ea5e9' },
    dns:                 { icon: '🧭', color: '#64748b' },
    bastion:             { icon: '🛡', color: '#ef4444' },
    iot_device:          { icon: '📟', color: '#06b6d4' },
    data_pipeline:       { icon: '🔀', color: '#9333ea' },
    scheduler:           { icon: '⏰', color: '#10b981' },
    search_service:      { icon: '🔎', color: '#0891b2' },
    service_mesh:        { icon: '🧬', color: '#3b82f6' },
  };

  const ALL_TYPES = Object.keys(TYPE_VISUALS);

  function getVisual(type) {
    return TYPE_VISUALS[type] || { icon: '📦', color: '#64748b' };
  }

  // Microsoft Threat Modeling Tool–style security properties. Each is answered
  // yes/no/unknown (or a level); a risky answer generates a tailored threat on
  // re-analysis. Fields shown are contextual to the component type.
  const YN = ['', 'yes', 'no'];
  const ATTR = {
    sensitivity:          { label: 'Data sensitivity', opts: ['', 'low', 'medium', 'high'] },
    internet_facing:      { label: 'Internet-facing', opts: YN },
    authenticates_users:  { label: 'Authenticates callers', opts: YN },
    enforces_authorization: { label: 'Enforces authorization', opts: YN },
    validates_input:      { label: 'Validates input', opts: YN },
    encodes_output:       { label: 'Encodes output', opts: YN },
    stores_credentials:   { label: 'Stores credentials/secrets', opts: YN },
    encrypted_at_rest:    { label: 'Encrypted at rest', opts: YN },
    has_backup:           { label: 'Backed up', opts: YN },
    logs_security_events: { label: 'Logs security events', opts: YN },
    multi_tenant:         { label: 'Multi-tenant', opts: YN },
    privilege_level:      { label: 'Privilege level', opts: ['', 'low', 'standard', 'elevated'] },
    provides_integrity:   { label: 'Provides integrity (signing/HMAC)', opts: YN },
    // Second wave
    csrf_protection:      { label: 'CSRF protection', opts: YN },
    rate_limited:         { label: 'Rate limited', opts: YN },
    mfa:                  { label: 'Multi-factor auth', opts: YN },
    handles_pii:          { label: 'Handles PII', opts: YN },
    handles_phi:          { label: 'Handles PHI (health)', opts: YN },
    handles_pci:          { label: 'Handles cardholder data', opts: YN },
    verifies_code_integrity: { label: 'Verifies code/artifact integrity', opts: YN },
    removable_media:      { label: 'On removable media', opts: YN },
    secure_error_handling: { label: 'Safe error handling', opts: YN },
    replay_protection:    { label: 'Replay protection (nonce/timestamp)', opts: YN },
    validates_certificates: { label: 'Validates TLS certificates', opts: YN },
    // Agentic AI properties (shown on agent / LLM / tool / memory / RAG components)
    autonomy_level:       { label: 'Autonomy level', opts: ['', 'suggest', 'act_with_approval', 'autonomous'] },
    tool_access:          { label: 'Tool access', opts: ['', 'none', 'read', 'write', 'exec'] },
    human_in_the_loop:    { label: 'Human-in-the-loop review', opts: YN },
    prompt_injection_defense: { label: 'Prompt-injection defense', opts: YN },
    output_validated:     { label: 'Validates model output before use', opts: YN },
    sandboxed:            { label: 'Runs sandboxed/isolated', opts: YN },
    can_spawn_agents:     { label: 'Can spawn other agents', opts: YN },
    ingests_untrusted_content: { label: 'Ingests untrusted content into context', opts: YN },
    memory_scope:         { label: 'Memory scope', opts: ['', 'session', 'per_user', 'cross_user', 'cross_tenant'] },
    content_source_trust: { label: 'Content/grounding source', opts: ['', 'curated', 'user_uploaded', 'web_scraped'] },
  };
  const STORE_TYPES = ['database', 'datastore', 'cache', 'queue', 'filesystem', 'object_storage', 'data_warehouse', 'vector_db', 'secrets_manager', 'search_service', 'agent_memory', 'knowledge_base'];
  const PROCESS_TYPES = ['api', 'webapp', 'mobile_app', 'service', 'worker', 'serverless', 'auth_service', 'admin_panel', 'api_gateway', 'container', 'kubernetes', 'llm', 'identity_provider', 'data_pipeline', 'scheduler', 'service_mesh', 'bastion', 'ai_agent', 'agent_orchestrator', 'llm_tool', 'mcp_server', 'retriever', 'guardrail'];
  const DEPLOYABLE_TYPES = ['serverless', 'container', 'kubernetes', 'service', 'worker'];
  // Which agentic attributes to show on which agentic component types.
  const AGENTIC_ATTRS = {
    ai_agent:           ['autonomy_level', 'tool_access', 'human_in_the_loop', 'prompt_injection_defense', 'output_validated', 'sandboxed', 'can_spawn_agents', 'ingests_untrusted_content'],
    agent_orchestrator: ['autonomy_level', 'human_in_the_loop', 'can_spawn_agents', 'output_validated'],
    llm:                ['ingests_untrusted_content', 'prompt_injection_defense', 'output_validated'],
    llm_tool:           ['tool_access', 'sandboxed', 'output_validated'],
    mcp_server:         ['tool_access', 'sandboxed'],
    retriever:          ['content_source_trust', 'ingests_untrusted_content'],
    knowledge_base:     ['content_source_trust'],
    agent_memory:       ['memory_scope'],
    vector_db:          ['memory_scope'],
    guardrail:          ['output_validated'],
  };

  // Flow protocol/auth are multi-value (defence-in-depth); authorization is single.
  const PROTOCOL_OPTIONS = ['HTTPS', 'HTTP', 'TCP', 'UDP', 'gRPC', 'WSS', 'WS', 'AMQP', 'MQTT', 'TLS', 'SSH'];
  const AUTH_OPTIONS = ['none', 'session', 'bearer', 'jwt', 'mtls', 'api_key', 'oauth', 'basic', 'iam', 'sso', 'credentials'];
  const AUTHZ_OPTIONS = ['', 'none', 'rbac', 'abac', 'rebac', 'acl', 'oauth_scopes', 'policy_engine'];

  function toArr(v) { return Array.isArray(v) ? v.slice() : (v ? [v] : []); }

  // Chip-toggle multi-select: click chips to add/remove values from an array field.
  function multiChips(field, options, selected) {
    const sel = toArr(selected).map(x => String(x).toLowerCase());
    return `<div class="dfd-multi" data-multi="${field}" style="display:flex;flex-wrap:wrap;gap:4px;margin-top:2px;">` +
      options.map(o => {
        const on = sel.includes(String(o).toLowerCase());
        return `<button type="button" data-multi-val="${o}" style="font-size:11px;padding:2px 9px;border-radius:999px;` +
          `border:1px solid ${on ? '#6366f1' : '#cbd5e1'};background:${on ? '#eef2ff' : '#fff'};` +
          `color:${on ? '#3730a3' : '#475569'};cursor:pointer;">${o}</button>`;
      }).join('') + `</div>`;
  }

  function componentAttrFields(type) {
    // PII/PHI/PCI data-handling questions apply to almost everything that touches data.
    const compliance = ['handles_pii', 'handles_phi', 'handles_pci'];
    const common = ['sensitivity', 'internet_facing', 'logs_security_events', ...compliance];
    const agentic = AGENTIC_ATTRS[type] || [];   // agent/LLM/tool/memory/RAG properties
    if (STORE_TYPES.includes(type)) {
      return [...common, 'stores_credentials', 'encrypted_at_rest', 'has_backup', 'removable_media', ...agentic];
    }
    if (PROCESS_TYPES.includes(type)) {
      const f = [...common, 'authenticates_users', 'enforces_authorization', 'validates_input',
                 'rate_limited', 'secure_error_handling', 'privilege_level', 'multi_tenant'];
      if (type === 'webapp') f.push('encodes_output', 'csrf_protection');
      if (type === 'api' || type === 'api_gateway') f.push('csrf_protection');
      if (type === 'auth_service' || type === 'identity_provider' || type === 'admin_panel') f.push('mfa');
      if (DEPLOYABLE_TYPES.includes(type)) f.push('verifies_code_integrity');
      return [...f, ...agentic];
    }
    return [...common, ...agentic];
  }

  function attrSelectsHtml(obj, fields) {
    return fields.map(k => {
      const a = ATTR[k]; if (!a) return '';
      const cur = obj[k] || '';
      const opts = a.opts.map(o => `<option value="${o}" ${cur === o ? 'selected' : ''}>${o === '' ? '— unknown —' : o}</option>`).join('');
      return `<label class="dfd-field"><span>${a.label}</span><select data-field="${k}" class="select">${opts}</select></label>`;
    }).join('');
  }

  // Auto layout. Each trust boundary becomes a left→right "band"; a band with more
  // than MAX_ROWS members wraps into a compact grid (several sub-columns) instead of
  // one very tall column, so a crowded boundary in a large system stays readable
  // rather than stacking 20+ nodes vertically. Mirrors the server's _auto_layout.
  const LAYOUT_MAX_ROWS = 6;
  function _gridDims(n) {
    return { rows: Math.min(Math.max(1, n), LAYOUT_MAX_ROWS), sub: Math.max(1, Math.ceil(n / LAYOUT_MAX_ROWS)) };
  }

  // Order nodes within each band by the barycenter (mean row) of their connected
  // neighbours, so flows connect nodes at similar heights and cross far less — the
  // classic layered-layout heuristic. Reorders the band arrays in place.
  function _barycenterOrder(bands, flows) {
    if (bands.length < 2 || !flows.length) return;
    const bandOf = {};
    bands.forEach((m, bi) => m.forEach(c => { bandOf[c.id] = bi; }));
    const nbr = {};
    flows.forEach(f => {
      if (bandOf[f.from] != null && bandOf[f.to] != null) {
        (nbr[f.from] = nbr[f.from] || []).push(f.to);
        (nbr[f.to] = nbr[f.to] || []).push(f.from);
      }
    });
    const rowOf = {};
    bands.forEach(m => m.forEach((c, i) => { rowOf[c.id] = i; }));
    const bary = c => {
      const rs = (nbr[c.id] || []).map(n => rowOf[n]).filter(r => r != null);
      return rs.length ? rs.reduce((a, b) => a + b, 0) / rs.length : rowOf[c.id];
    };
    for (let it = 0; it < 4; it++) {
      bands.forEach(m => { m.sort((a, b) => bary(a) - bary(b)); m.forEach((c, i) => { rowOf[c.id] = i; }); });
    }
  }
  function autoLayout(system, layers) {
    const components = system.components || [];
    const boundaries = system.trust_boundaries || [];
    const layout = system.layout || {};
    const need = components.filter(c => !layout[c.id]);
    if (need.length === 0) return layout;

    const ROW_GAP = COMP_H + 30;      // vertical spacing between rows
    const SUB_COL_GAP = COMP_W + 70;  // horizontal spacing between sub-columns
    const BAND_GAP = 80;              // gap between adjacent boundaries
    const MARGIN = 50;

    const placeBand = (members, x0, top, tallestRows) => {
      const { rows, sub } = _gridDims(members.length);
      const y0 = top + (tallestRows - rows) * ROW_GAP / 2;   // vertically centre the grid
      members.forEach((c, i) => {
        const si = Math.floor(i / rows), ri = i % rows;      // fill top→bottom, then next sub-column
        layout[c.id] = { x: snap(x0 + si * SUB_COL_GAP), y: snap(y0 + ri * ROW_GAP) };
      });
      return sub * SUB_COL_GAP;                              // band width consumed
    };

    if (boundaries.length > 0 && layers.boundaries !== false) {
      const assigned = new Set();
      const bands = [];
      boundaries.forEach(b => {
        const inside = (b.contains || []).map(cid => need.find(c => c.id === cid)).filter(Boolean);
        if (inside.length) { bands.push(inside); inside.forEach(c => assigned.add(c.id)); }
      });
      const unbounded = need.filter(c => !assigned.has(c.id));
      if (unbounded.length) bands.push(unbounded);           // stray nodes → trailing band
      _barycenterOrder(bands, system.data_flows || []);      // reduce edge crossings
      const tallest = Math.max(1, ...bands.map(m => _gridDims(m.length).rows));
      const top = MARGIN + 44;                               // room for the boundary label
      let x = MARGIN;
      bands.forEach(members => { x += placeBand(members, x, top, tallest) + BAND_GAP; });
    } else {
      // No boundaries — one compact grid, wrapping every MAX_ROWS+2 down a column.
      const perCol = LAYOUT_MAX_ROWS + 2;
      need.forEach((c, i) => {
        layout[c.id] = { x: snap(MARGIN + Math.floor(i / perCol) * SUB_COL_GAP),
                         y: snap(MARGIN + (i % perCol) * ROW_GAP) };
      });
    }
    return layout;
  }

  function snap(v) { return Math.round(v / GRID) * GRID; }

  function escapeAttr(s) {
    if (s == null) return '';
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]);
  }

  // ========================================================================
  //  Editor instance
  // ========================================================================
  function mount(container, initialSystem, options = {}) {
    const opts = {
      readOnly: false,
      sourceText: '',
      onChange: function () {},
      ...options,
    };

    // Deep clone so we don't mutate caller's object
    let system = JSON.parse(JSON.stringify(initialSystem || {}));
    system.components = system.components || [];
    system.data_flows = system.data_flows || [];
    system.trust_boundaries = system.trust_boundaries || [];
    system.layout = system.layout || {};

    // Labels default OFF: numbered badges keep the canvas readable; users who want
    // per-edge text labels can switch them on with the "Labels" toggle.
    let layers = { boundaries: true, encryption: true, labels: false };
    let selected = null;            // { kind: 'component'|'flow'|'boundary', id }
    let dragging = null;            // { id, offsetX, offsetY }
    let flowDrawing = null;         // { fromId, mouseX, mouseY }
    // Navigation is viewBox-based (not CSS scale): this makes Fit, pan and zoom
    // consistent and keeps pointer math (getScreenCTM) correct at any zoom.
    const view = { x: 0, y: 0, w: CANVAS_W, h: CANVAS_H };

    // Toolbar + canvas + side panel
    container.innerHTML = '';
    container.style.position = 'relative';

    const tpl = document.createElement('div');
    tpl.className = 'dfd-editor';
    tpl.innerHTML = `
      <div class="dfd-toolbar">
        ${opts.readOnly ? '' : `
          <div class="dfd-toolbar-group">
            <button data-act="add-component" class="btn btn-sm btn-ghost" title="Add component">＋ Component</button>
            <button data-act="add-flow" class="btn btn-sm btn-ghost" title="Add data flow (then click two components)">→ Flow</button>
            <button data-act="add-boundary" class="btn btn-sm btn-ghost" title="Add trust boundary">🛡 Boundary</button>
          </div>
          <div class="dfd-toolbar-divider"></div>
          <div class="dfd-toolbar-group">
            <button data-act="reinfer-heuristic" class="btn btn-sm btn-ghost" title="Re-infer trust boundaries from rules">↻ Re-infer</button>
            <button data-act="reinfer-llm" class="btn btn-sm btn-ghost" title="Re-infer trust boundaries with AI" id="dfd-btn-llm">🤖 Infer with AI</button>
          </div>
          <div class="dfd-toolbar-divider"></div>
          <div class="dfd-toolbar-group">
            <button data-act="auto-layout" class="btn btn-sm btn-ghost" title="Auto-arrange components">⚄ Auto-layout</button>
          </div>
          <div class="dfd-toolbar-divider"></div>
        `}
        <div class="dfd-toolbar-group dfd-layer-toggles">
          <label class="dfd-layer-toggle"><input type="checkbox" data-layer="boundaries" checked> Boundaries</label>
          <label class="dfd-layer-toggle"><input type="checkbox" data-layer="encryption" checked> Encryption icons</label>
          <label class="dfd-layer-toggle"><input type="checkbox" data-layer="labels"> Flow labels</label>
        </div>
        <div class="dfd-toolbar-spacer"></div>
        <div class="dfd-toolbar-group">
          <button data-act="help" class="btn btn-sm btn-ghost" title="What do the shapes and colours mean?">? Guide</button>
          <button data-act="fit" class="btn btn-sm btn-ghost" title="Fit the whole diagram in view">⊡ Fit</button>
          <button data-act="zoom-out" class="btn btn-sm btn-ghost" title="Zoom out">−</button>
          <span id="dfd-zoom-label" class="text-xs text-light" style="min-width: 36px; text-align: center;">100%</span>
          <button data-act="zoom-in" class="btn btn-sm btn-ghost" title="Zoom in">+</button>
        </div>
      </div>
      <div class="dfd-mode-banner hidden" id="dfd-mode-banner"></div>
      <div class="dfd-canvas-wrap" style="position:relative;overflow:hidden;">
        <div id="dfd-empty" class="hidden" style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;pointer-events:none;z-index:2;">
          <div style="text-align:center;max-width:340px;background:rgba(255,255,255,0.92);border:1px dashed #cbd5e1;border-radius:12px;padding:20px 24px;pointer-events:auto;">
            <div style="font-size:1.6rem;margin-bottom:6px;">🗺️</div>
            <div style="font-weight:700;color:#334155;margin-bottom:4px;">Your diagram is empty</div>
            <div style="font-size:.85rem;color:#64748b;line-height:1.5;">${opts.readOnly ? 'No components have been added to this model yet.' : 'Click <b>＋ Component</b> to add your first element, then <b>→ Flow</b> to connect two components. <b>? Guide</b> explains the notation.'}</div>
          </div>
        </div>
        <div id="dfd-help" class="hidden" style="position:absolute;top:8px;right:8px;width:250px;background:#fff;border:1px solid #e2e8f0;border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.12);padding:12px 14px;z-index:3;font-size:.8rem;color:#334155;line-height:1.5;">
          <div style="font-weight:700;margin-bottom:6px;display:flex;justify-content:space-between;align-items:center;">Notation<span data-act="help-close" style="cursor:pointer;color:#94a3b8;">✕</span></div>
          <div style="margin:3px 0;"><b>Rounded box</b> = process/service</div>
          <div style="margin:3px 0;"><b>Open box</b> = data store</div>
          <div style="margin:3px 0;"><b>Sharp box</b> = external entity / user</div>
          <div style="margin:3px 0;"><b>Dashed area</b> = trust boundary</div>
          <div style="margin:3px 0;"><span style="display:inline-block;width:13px;height:13px;border-radius:50%;background:#ef4444;vertical-align:middle;"></span> red badge/line = unencrypted or boundary-crossing flow</div>
          <div style="margin:3px 0;"><span style="display:inline-block;width:13px;height:13px;border-radius:50%;background:#64748b;vertical-align:middle;"></span> grey badge = encrypted internal flow</div>
          <div style="margin-top:6px;color:#64748b;">Hover a flow for its details · drag components to arrange · scroll/Fit to navigate.</div>
        </div>
        <svg class="dfd-canvas" viewBox="0 0 ${CANVAS_W} ${CANVAS_H}" preserveAspectRatio="xMidYMid meet">
          <defs>
            <pattern id="dfd-grid" width="${GRID}" height="${GRID}" patternUnits="userSpaceOnUse">
              <path d="M ${GRID} 0 L 0 0 0 ${GRID}" fill="none" stroke="rgba(99,102,241,0.06)" stroke-width="0.5"/>
            </pattern>
            <marker id="dfd-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#475569"/>
            </marker>
            <marker id="dfd-arrow-red" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#dc2626"/>
            </marker>
          </defs>
          <rect width="100%" height="100%" fill="url(#dfd-grid)"/>
          <g class="dfd-boundaries-layer"></g>
          <g class="dfd-flows-layer"></g>
          <g class="dfd-components-layer"></g>
          <g class="dfd-overlay-layer"></g>
        </svg>
        <div class="dfd-side-panel hidden" id="dfd-side-panel"></div>
      </div>
    `;
    container.appendChild(tpl);

    const svg = container.querySelector('svg.dfd-canvas');
    const sidePanel = container.querySelector('#dfd-side-panel');

    // ---- Focus & trace ------------------------------------------------------
    // Hover = a transient peek at a node's DIRECT flows (only on a busy diagram).
    // Click = pin a TRACE of the node's complete journey: every component up- and
    // down-stream that the node can reach or be reached from (graph traversal), so
    // a 30-component system can be followed one lineage at a time. A pinned trace
    // survives hovering elsewhere; click empty canvas (or the node again) to clear.
    const FOCUS_MIN_FLOWS = 8;
    let tracedNode = null;

    function _layers() {
      return [svg.querySelector('.dfd-flows-layer'), svg.querySelector('.dfd-components-layer')];
    }
    function _paint(nodeIds, flowPred) {
      const [fl, cl] = _layers();
      if (!fl || !cl) return;
      fl.querySelectorAll('.dfd-flow').forEach(gf =>
        gf.classList.toggle('dfd-flow-focus', flowPred(gf.dataset.from, gf.dataset.to)));
      cl.querySelectorAll('.dfd-component').forEach(n =>
        n.classList.toggle('dfd-node-focus', nodeIds.has(n.dataset.componentId)));
      fl.classList.add('dfd-focusing');
      cl.classList.add('dfd-focusing');
    }
    function _clearPaint() {
      _layers().forEach(layer => {
        if (!layer) return;
        layer.classList.remove('dfd-focusing');
        layer.querySelectorAll('.dfd-flow-focus, .dfd-node-focus')
          .forEach(e => e.classList.remove('dfd-flow-focus', 'dfd-node-focus'));
      });
    }
    // Full up- and down-stream reachable set from `id` over the directed flow graph.
    function _journey(id) {
      const fwd = new Map(), rev = new Map();
      (system.data_flows || []).forEach(f => {
        if (!fwd.has(f.from)) fwd.set(f.from, []);
        if (!rev.has(f.to)) rev.set(f.to, []);
        fwd.get(f.from).push(f.to);
        rev.get(f.to).push(f.from);
      });
      const walk = (start, adj) => {
        const seen = new Set(), stack = [start];
        while (stack.length) {
          const cur = stack.pop();
          for (const nxt of (adj.get(cur) || [])) if (!seen.has(nxt)) { seen.add(nxt); stack.push(nxt); }
        }
        return seen;
      };
      const nodes = new Set([id, ...walk(id, fwd), ...walk(id, rev)]);
      return nodes;
    }
    function focusNode(id) {
      if (dragging || flowDrawing || tracedNode) return;   // a pinned trace wins over hover
      const [fl] = _layers();
      if (!fl || fl.querySelectorAll('.dfd-flow').length < FOCUS_MIN_FLOWS) return;
      const nb = new Set([id]);
      fl.querySelectorAll('.dfd-flow').forEach(gf => {
        if (gf.dataset.from === id || gf.dataset.to === id) { nb.add(gf.dataset.from); nb.add(gf.dataset.to); }
      });
      _paint(nb, (a, b) => a === id || b === id);
    }
    function clearFocus() {
      if (tracedNode) { applyTrace(tracedNode); return; }   // don't wipe a pinned trace
      _clearPaint();
    }
    function _traceBadge(nNodes, nFlows) {
      let b = container.querySelector('.dfd-trace-badge');
      if (nNodes == null) { if (b) b.remove(); return; }
      if (!b) {
        b = document.createElement('div');
        b.className = 'dfd-trace-badge';
        container.querySelector('.dfd-canvas-wrap')?.appendChild(b) || container.appendChild(b);
      }
      b.innerHTML = `<strong>Trace</strong> · ${nNodes} component${nNodes !== 1 ? 's' : ''} · ` +
                    `${nFlows} flow${nFlows !== 1 ? 's' : ''} <span class="dfd-trace-clear">clear ✕</span>`;
      b.querySelector('.dfd-trace-clear')?.addEventListener('click', (e) => { e.stopPropagation(); clearTrace(); });
    }
    function applyTrace(id) {
      const nodes = _journey(id);
      let nFlows = 0;
      _paint(nodes, (a, b) => {
        const on = nodes.has(a) && nodes.has(b);
        if (on) nFlows++;
        return on;
      });
      _traceBadge(nodes.size, nFlows);
    }
    function traceNode(id) {
      tracedNode = id;
      applyTrace(id);
    }
    function clearTrace() {
      tracedNode = null;
      _clearPaint();
      _traceBadge(null);
    }
    function toggleTrace(id) {
      if (tracedNode === id) clearTrace(); else traceNode(id);
    }

    // Auto-layout for any components without positions
    system.layout = autoLayout(system, layers);

    // ----------------------------------------------------------------------
    //  Render
    // ----------------------------------------------------------------------
    function render() {
      const boundariesLayer = svg.querySelector('.dfd-boundaries-layer');
      const flowsLayer = svg.querySelector('.dfd-flows-layer');
      const componentsLayer = svg.querySelector('.dfd-components-layer');
      const overlayLayer = svg.querySelector('.dfd-overlay-layer');

      boundariesLayer.innerHTML = '';
      flowsLayer.innerHTML = '';
      componentsLayer.innerHTML = '';
      overlayLayer.innerHTML = '';

      // Trust boundaries (rendered first so they appear behind)
      if (layers.boundaries) {
        (system.trust_boundaries || []).forEach(b => {
          const ids = b.contains || [];
          const positions = ids.map(id => system.layout[id]).filter(Boolean);
          if (positions.length === 0) return;

          const minX = Math.min(...positions.map(p => p.x)) - BOUNDARY_PADDING;
          const minY = Math.min(...positions.map(p => p.y)) - BOUNDARY_PADDING - 24;
          const maxX = Math.max(...positions.map(p => p.x)) + COMP_W + BOUNDARY_PADDING;
          const maxY = Math.max(...positions.map(p => p.y)) + COMP_H + BOUNDARY_PADDING;

          const isSelected = selected && selected.kind === 'boundary' && selected.id === b.id;
          const stroke = isSelected ? '#6366f1' : '#f59e0b';
          const sw = isSelected ? 3 : 2;

          const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
          g.setAttribute('class', 'dfd-boundary');
          g.setAttribute('data-boundary-id', b.id);
          g.innerHTML = `
            <rect x="${minX}" y="${minY}" width="${maxX - minX}" height="${maxY - minY}"
                  fill="rgba(254, 243, 199, 0.3)" stroke="${stroke}" stroke-width="${sw}"
                  stroke-dasharray="8,4" rx="14" ry="14"
                  style="cursor: pointer;"/>
            <rect x="${minX + 8}" y="${minY - 12}" width="${(b.name || '').length * 7 + 30}" height="22"
                  fill="${stroke}" rx="11" ry="11"/>
            <text x="${minX + 18}" y="${minY + 3}" fill="white" font-size="11" font-weight="600">
              🛡 ${escapeAttr(b.name || 'Boundary')}
            </text>
          `;
          boundariesLayer.appendChild(g);

          if (!opts.readOnly) {
            g.addEventListener('click', (e) => {
              e.stopPropagation();
              selectBoundary(b.id);
            });
          }
        });
      }

      // Data flows. Numbered badges (keyed to the flow legend / click-to-inspect)
      // replace inline text labels, which overlap into unreadable clutter on large
      // models — matching the server-rendered report DFD.
      const compBoundary = {};
      (system.trust_boundaries || []).forEach(b =>
        (b.contains || []).forEach(cid => { compBoundary[cid] = b.id; }));
      const compName = {};
      (system.components || []).forEach(c => { compName[c.id] = c.name || c.id; });
      (system.data_flows || []).forEach((f, _flowIdx) => {
        const fromPos = system.layout[f.from];
        const toPos = system.layout[f.to];
        if (!fromPos || !toPos) return;
        const flowNum = _flowIdx + 1;
        const crossesBoundary = compBoundary[f.from] !== compBoundary[f.to];

        // Center points
        const x1 = fromPos.x + COMP_W / 2;
        const y1 = fromPos.y + COMP_H / 2;
        const x2 = toPos.x + COMP_W / 2;
        const y2 = toPos.y + COMP_H / 2;

        // Adjust endpoint to box edge so arrow doesn't enter the box
        const dx = x2 - x1, dy = y2 - y1;
        const len = Math.sqrt(dx * dx + dy * dy) || 1;
        const adjX2 = x2 - (dx / len) * (COMP_W / 2 + 4);
        const adjY2 = y2 - (dy / len) * (COMP_H / 2 + 4);
        const adjX1 = x1 + (dx / len) * (COMP_W / 2 + 4);
        const adjY1 = y1 + (dy / len) * (COMP_H / 2 + 4);

        const isSelected = selected && selected.kind === 'flow' && selected.id === f.id;
        const isEncrypted = f.encrypted !== false;
        const stroke = isEncrypted ? '#475569' : '#dc2626';
        const dash = isEncrypted ? '' : '6,4';
        const arrow = isEncrypted ? 'url(#dfd-arrow)' : 'url(#dfd-arrow-red)';

        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('class', 'dfd-flow');
        g.setAttribute('data-flow-id', f.id);
        g.setAttribute('data-from', f.from);
        g.setAttribute('data-to', f.to);

        // Native hover tooltip: inspect a flow (endpoints, protocol, auth, encryption)
        // without clicking — the numbered badge and line both carry it.
        const sec = (isEncrypted ? 'encrypted' : 'plaintext') + (crossesBoundary ? ', crosses boundary' : '');
        const protoStr = toArr(f.protocol).join('+') || '—';
        const authStr = toArr(f.auth).join('+') || 'none';
        const authzStr = f.authorization ? ` · authz: ${f.authorization}` : '';
        const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
        title.textContent = `[${flowNum}] ${compName[f.from] || f.from} → ${compName[f.to] || f.to}`
          + ` · ${protoStr} · auth: ${authStr}${authzStr} · ${sec}`;
        g.appendChild(title);

        // Curved edge: bow the line along its dominant axis so overlapping flows
        // fan out and separate visually instead of stacking into a straight-line mesh.
        const _horiz = Math.abs(dx) >= Math.abs(dy);
        const _off = 0.42;
        const c1x = _horiz ? adjX1 + (adjX2 - adjX1) * _off : adjX1;
        const c1y = _horiz ? adjY1 : adjY1 + (adjY2 - adjY1) * _off;
        const c2x = _horiz ? adjX2 - (adjX2 - adjX1) * _off : adjX2;
        const c2y = _horiz ? adjY2 : adjY2 - (adjY2 - adjY1) * _off;
        const pathD = `M ${adjX1} ${adjY1} C ${c1x} ${c1y}, ${c2x} ${c2y}, ${adjX2} ${adjY2}`;
        const bez = (t, p0, p1, p2, p3) => { const m = 1 - t; return m * m * m * p0 + 3 * m * m * t * p1 + 3 * m * t * t * p2 + t * t * t * p3; };

        // Hit area (transparent thick path following the curve)
        const hit = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        hit.setAttribute('d', pathD);
        hit.setAttribute('fill', 'none');
        hit.setAttribute('stroke', 'transparent');
        hit.setAttribute('stroke-width', 14);
        hit.style.cursor = 'pointer';
        g.appendChild(hit);

        const line = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        line.setAttribute('d', pathD);
        line.setAttribute('fill', 'none');
        line.setAttribute('stroke', stroke);
        line.setAttribute('stroke-width', isSelected ? 2.6 : 1.6);
        // Semi-transparent so a dense diagram reads as layered depth, not a hard web.
        line.setAttribute('stroke-opacity', isEncrypted ? (isSelected ? 0.95 : 0.5) : 0.72);
        if (dash) line.setAttribute('stroke-dasharray', dash);
        line.setAttribute('marker-end', arrow);
        g.appendChild(line);

        // Numbered risk badge at midpoint (doubles as the flow's click target).
        // Red = unencrypted or boundary-crossing (only when the Encryption layer is
        // on); otherwise slate. Keeps the canvas legible no matter how dense it gets.
        {
          // Stagger the badge along the curve (by flow number) so converging flows
          // don't stack their badges at a single point. Evaluated on the bezier so
          // the badge sits exactly on the drawn line.
          const bt = 0.34 + ((flowNum - 1) % 3) * 0.13;
          const mx = bez(bt, adjX1, c1x, c2x, adjX2);
          const my = bez(bt, adjY1, c1y, c2y, adjY2);
          const risky = (!isEncrypted || crossesBoundary);
          const badgeFill = (layers.encryption && risky) ? '#ef4444' : '#64748b';
          const badgeBg = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
          badgeBg.setAttribute('cx', mx);
          badgeBg.setAttribute('cy', my);
          badgeBg.setAttribute('r', 9.5);
          badgeBg.setAttribute('fill', badgeFill);
          badgeBg.setAttribute('stroke', 'white');
          badgeBg.setAttribute('stroke-width', 1.5);
          g.appendChild(badgeBg);
          const badgeText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
          badgeText.setAttribute('x', mx);
          badgeText.setAttribute('y', my + 3.3);
          badgeText.setAttribute('text-anchor', 'middle');
          badgeText.setAttribute('font-size', 10.5);
          badgeText.setAttribute('font-weight', '700');
          badgeText.setAttribute('fill', 'white');
          badgeText.textContent = flowNum;
          g.appendChild(badgeText);
        }

        // Optional full text label (off by default; toggle "Labels" to show).
        if (layers.labels && f.label) {
          const labelX = (adjX1 + adjX2) / 2;
          const labelY = (adjY1 + adjY2) / 2 - 14;
          const labelBg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
          const labelW = (f.label || '').length * 5.5 + 10;
          labelBg.setAttribute('x', labelX - labelW / 2);
          labelBg.setAttribute('y', labelY - 9);
          labelBg.setAttribute('width', labelW);
          labelBg.setAttribute('height', 14);
          labelBg.setAttribute('fill', 'rgba(255,255,255,0.95)');
          labelBg.setAttribute('rx', 2);
          g.appendChild(labelBg);
          const labelText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
          labelText.setAttribute('x', labelX);
          labelText.setAttribute('y', labelY + 1);
          labelText.setAttribute('text-anchor', 'middle');
          labelText.setAttribute('font-size', 9);
          labelText.setAttribute('fill', '#475569');
          labelText.textContent = f.label;
          g.appendChild(labelText);
        }

        flowsLayer.appendChild(g);

        if (!opts.readOnly) {
          g.addEventListener('click', (e) => {
            e.stopPropagation();
            selectFlow(f.id);
          });
        }
      });

      // Components
      (system.components || []).forEach(c => {
        const pos = system.layout[c.id];
        if (!pos) return;
        const v = getVisual(c.type);
        const isSelected = selected && selected.kind === 'component' && selected.id === c.id;

        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('class', 'dfd-component');
        g.setAttribute('data-component-id', c.id);
        g.setAttribute('transform', `translate(${pos.x}, ${pos.y})`);
        if (!opts.readOnly) g.style.cursor = 'grab';

        const stroke = isSelected ? '#6366f1' : '#cbd5e1';
        const sw = isSelected ? 2.5 : 1;

        g.innerHTML = `
          <rect width="${COMP_W}" height="${COMP_H}" rx="10" ry="10"
                fill="white" stroke="${stroke}" stroke-width="${sw}"
                style="filter: drop-shadow(0 1px 3px rgba(0,0,0,0.1));"/>
          <rect x="0" y="0" width="6" height="${COMP_H}" rx="10" ry="10" fill="${v.color}"/>
          <text x="${COMP_W / 2}" y="22" text-anchor="middle" font-size="14">${v.icon}</text>
          <text x="${COMP_W / 2}" y="42" text-anchor="middle" font-size="11" font-weight="600" fill="#0f172a">
            ${escapeAttr((c.name || '').slice(0, 16))}
          </text>
          <text x="${COMP_W / 2}" y="56" text-anchor="middle" font-size="9" fill="#64748b">
            ${escapeAttr(c.type || '')}
          </text>
          ${opts.readOnly ? '' : `
            <circle class="dfd-connect-handle" cx="${COMP_W}" cy="${COMP_H / 2}" r="6"
                    fill="#6366f1" stroke="#fff" stroke-width="1.5" opacity="0.85"
                    style="cursor:crosshair;"><title>Drag to another component to connect a flow</title></circle>`}
        `;
        componentsLayer.appendChild(g);

        // Hover fades unrelated flows (quick peek); click pins the full-journey
        // trace. Both work in read-only report view too.
        g.addEventListener('mouseenter', () => focusNode(c.id));
        g.addEventListener('mouseleave', clearFocus);

        if (opts.readOnly) {
          g.style.cursor = 'pointer';
          g.addEventListener('click', (e) => { e.stopPropagation(); toggleTrace(c.id); });
        } else {
          g.style.touchAction = 'none';
          // Drag the connect handle → draw a flow to whatever component you release on.
          const handle = g.querySelector('.dfd-connect-handle');
          if (handle) handle.addEventListener('pointerdown', (e) => startConnectDrag(e, c.id));
          g.addEventListener('pointerdown', (e) => beginDrag(e, c.id));
          g.addEventListener('click', (e) => {
            e.stopPropagation();
            // Click without drag: complete a connection, else pin the journey trace + select.
            if (!dragging || !dragging.moved) {
              if (flowDrawing) {
                completeFlow(c.id);
              } else {
                toggleTrace(c.id);
                selectComponent(c.id);
              }
            }
          });
        }
      });

      // Empty-state guide toggles with content
      const emptyEl = container.querySelector('#dfd-empty');
      if (emptyEl) emptyEl.classList.toggle('hidden', (system.components || []).length > 0);

      // Flow-drawing overlay
      if (flowDrawing) {
        const fromPos = system.layout[flowDrawing.fromId];
        if (fromPos) {
          const x1 = fromPos.x + COMP_W / 2;
          const y1 = fromPos.y + COMP_H / 2;
          const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
          line.setAttribute('x1', x1);
          line.setAttribute('y1', y1);
          line.setAttribute('x2', flowDrawing.mouseX);
          line.setAttribute('y2', flowDrawing.mouseY);
          line.setAttribute('stroke', '#6366f1');
          line.setAttribute('stroke-width', 2);
          line.setAttribute('stroke-dasharray', '4,4');
          line.style.pointerEvents = 'none';
          overlayLayer.appendChild(line);
        }
      }

      // Re-apply a pinned journey trace after a re-render (drops it if the traced
      // component was removed) so the highlight and badge never go stale.
      if (tracedNode) {
        if ((system.components || []).some(c => c.id === tracedNode)) applyTrace(tracedNode);
        else clearTrace();
      }
    }

    // ----------------------------------------------------------------------
    //  Drag-to-reposition
    // ----------------------------------------------------------------------
    function clientToCanvas(evt) {
      const pt = svg.createSVGPoint();
      pt.x = evt.clientX;
      pt.y = evt.clientY;
      const ctm = svg.getScreenCTM();
      if (!ctm) return { x: 0, y: 0 };
      const inv = ctm.inverse();
      const sp = pt.matrixTransform(inv);
      return { x: sp.x, y: sp.y };
    }

    function beginDrag(e, componentId) {
      if (opts.readOnly) return;
      e.preventDefault();
      const pos = system.layout[componentId];
      const cp = clientToCanvas(e);
      dragging = {
        id: componentId,
        offsetX: cp.x - pos.x,
        offsetY: cp.y - pos.y,
        moved: false,
      };
      window.addEventListener('pointermove', onDrag);
      window.addEventListener('pointerup', endDrag);
    }

    function onDrag(e) {
      if (!dragging) return;
      const cp = clientToCanvas(e);
      const newX = snap(cp.x - dragging.offsetX);
      const newY = snap(cp.y - dragging.offsetY);
      const cur = system.layout[dragging.id];
      if (cur.x !== newX || cur.y !== newY) {
        system.layout[dragging.id] = { x: newX, y: newY };
        dragging.moved = true;
        render();
      }
    }

    function endDrag(e) {
      window.removeEventListener('pointermove', onDrag);
      window.removeEventListener('pointerup', endDrag);
      if (dragging && dragging.moved) {
        // Re-compute boundary membership: which boundary is the dropped
        // component visually inside? Reassign if it changed.
        reassignBoundaryByPosition(dragging.id);
        opts.onChange(getSystem());
      }
      dragging = null;
    }

    function reassignBoundaryByPosition(componentId) {
      const pos = system.layout[componentId];
      if (!pos) return;
      const cx = pos.x + COMP_W / 2;
      const cy = pos.y + COMP_H / 2;

      let target = null;
      for (const b of (system.trust_boundaries || [])) {
        const ids = (b.contains || []).filter(id => id !== componentId);
        const positions = ids.map(id => system.layout[id]).filter(Boolean);
        if (positions.length === 0) continue;
        const minX = Math.min(...positions.map(p => p.x)) - BOUNDARY_PADDING;
        const minY = Math.min(...positions.map(p => p.y)) - BOUNDARY_PADDING - 24;
        const maxX = Math.max(...positions.map(p => p.x)) + COMP_W + BOUNDARY_PADDING;
        const maxY = Math.max(...positions.map(p => p.y)) + COMP_H + BOUNDARY_PADDING;
        if (cx >= minX && cx <= maxX && cy >= minY && cy <= maxY) {
          target = b.id;
          break;
        }
      }

      // Already in target? bail
      const currentBoundary = (system.trust_boundaries || []).find(b => (b.contains || []).includes(componentId));
      if (currentBoundary && currentBoundary.id === target) return;

      // Remove from current, add to target
      (system.trust_boundaries || []).forEach(b => {
        b.contains = (b.contains || []).filter(id => id !== componentId);
      });
      if (target) {
        const tb = system.trust_boundaries.find(b => b.id === target);
        if (tb) tb.contains = (tb.contains || []).concat([componentId]);
      }
      // Drop empty boundaries
      system.trust_boundaries = system.trust_boundaries.filter(b => (b.contains || []).length > 0);
      render();
    }

    // ----------------------------------------------------------------------
    //  Selection + side panel
    // ----------------------------------------------------------------------
    function selectComponent(id) {
      selected = { kind: 'component', id };
      render();
      showComponentPanel(id);
    }
    function selectFlow(id) {
      selected = { kind: 'flow', id };
      render();
      showFlowPanel(id);
    }
    function selectBoundary(id) {
      selected = { kind: 'boundary', id };
      render();
      showBoundaryPanel(id);
    }
    function deselect() {
      selected = null;
      render();
      hidePanel();
    }

    function hidePanel() {
      sidePanel.classList.add('hidden');
      sidePanel.innerHTML = '';
    }

    function showComponentPanel(id) {
      const c = system.components.find(x => x.id === id);
      if (!c) return hidePanel();
      sidePanel.classList.remove('hidden');
      sidePanel.innerHTML = `
        <div class="dfd-panel-header">
          <div class="dfd-panel-title">Component</div>
          <button class="dfd-panel-close" data-act="close">✕</button>
        </div>
        <div class="dfd-panel-body">
          <label class="dfd-field">
            <span>Name</span>
            <input type="text" data-field="name" value="${escapeAttr(c.name || '')}" class="input"/>
          </label>
          <label class="dfd-field">
            <span>Type</span>
            <select data-field="type" class="select">
              ${ALL_TYPES.map(t => `<option value="${t}" ${c.type === t ? 'selected' : ''}>${t}</option>`).join('')}
            </select>
          </label>
          <label class="dfd-field">
            <span>Description</span>
            <textarea data-field="description" rows="3" class="input">${escapeAttr(c.description || '')}</textarea>
          </label>
          <details class="dfd-attrs" open>
            <summary style="cursor:pointer;font-size:0.8125rem;font-weight:600;margin:4px 0;">🛡 Security attributes</summary>
            <div class="text-xs text-light" style="margin-bottom:6px;">Answer what you know — a risky answer adds a specific threat when you re-analyze.</div>
            ${attrSelectsHtml(c, componentAttrFields(c.type))}
          </details>
          ${opts.readOnly ? '' : `
            <button data-act="delete" class="btn btn-danger btn-sm" style="width: 100%; margin-top: 8px;">Delete component</button>
          `}
        </div>
      `;
      wirePanelEvents('component', id);
    }

    function showFlowPanel(id) {
      const f = system.data_flows.find(x => x.id === id);
      if (!f) return hidePanel();
      sidePanel.classList.remove('hidden');
      const fromName = (system.components.find(c => c.id === f.from) || {}).name || f.from;
      const toName = (system.components.find(c => c.id === f.to) || {}).name || f.to;
      sidePanel.innerHTML = `
        <div class="dfd-panel-header">
          <div>
            <div class="dfd-panel-title">Data flow</div>
            <div class="text-xs text-light" style="margin-top:2px;">${escapeAttr(fromName)} → ${escapeAttr(toName)}</div>
          </div>
          <button class="dfd-panel-close" data-act="close">✕</button>
        </div>
        <div class="dfd-panel-body">
          <label class="dfd-field">
            <span>From</span>
            <select data-field="from" class="select">
              ${system.components.map(c => `<option value="${c.id}" ${f.from === c.id ? 'selected' : ''}>${escapeAttr(c.name || c.id)}</option>`).join('')}
            </select>
          </label>
          <label class="dfd-field">
            <span>To</span>
            <select data-field="to" class="select">
              ${system.components.map(c => `<option value="${c.id}" ${f.to === c.id ? 'selected' : ''}>${escapeAttr(c.name || c.id)}</option>`).join('')}
            </select>
          </label>
          <label class="dfd-field">
            <span>Label</span>
            <input type="text" data-field="label" value="${escapeAttr(f.label || '')}" class="input"/>
          </label>
          <div class="dfd-field">
            <span>Protocol(s)</span>
            ${multiChips('protocol', PROTOCOL_OPTIONS, f.protocol)}
          </div>
          <div class="dfd-field">
            <span>Authentication (select all that apply)</span>
            ${multiChips('auth', AUTH_OPTIONS, f.auth)}
          </div>
          <label class="dfd-field">
            <span>Authorization model</span>
            <select data-field="authorization" class="select">
              ${AUTHZ_OPTIONS.map(o => `<option value="${o}" ${(f.authorization || '') === o ? 'selected' : ''}>${o || '— unspecified —'}</option>`).join('')}
            </select>
          </label>
          <label class="dfd-field-checkbox">
            <input type="checkbox" data-field="encrypted" ${f.encrypted !== false ? 'checked' : ''}>
            <span>Encrypted in transit</span>
          </label>
          <details class="dfd-attrs" open>
            <summary style="cursor:pointer;font-size:0.8125rem;font-weight:600;margin:4px 0;">🛡 Security attributes</summary>
            <div class="text-xs text-light" style="margin-bottom:6px;">A risky answer adds a specific threat when you re-analyze.</div>
            ${attrSelectsHtml(f, ['provides_integrity', 'validates_input', 'replay_protection', 'validates_certificates'])}
          </details>
          ${opts.readOnly ? '' : `
            <button data-act="delete" class="btn btn-danger btn-sm" style="width: 100%; margin-top: 8px;">Delete flow</button>
          `}
        </div>
      `;
      wirePanelEvents('flow', id);
    }

    function showBoundaryPanel(id) {
      const b = system.trust_boundaries.find(x => x.id === id);
      if (!b) return hidePanel();
      sidePanel.classList.remove('hidden');
      sidePanel.innerHTML = `
        <div class="dfd-panel-header">
          <div class="dfd-panel-title">Trust boundary</div>
          <button class="dfd-panel-close" data-act="close">✕</button>
        </div>
        <div class="dfd-panel-body">
          <label class="dfd-field">
            <span>Name</span>
            <input type="text" data-field="name" value="${escapeAttr(b.name || '')}" class="input"/>
          </label>
          <label class="dfd-field">
            <span>Description</span>
            <textarea data-field="description" rows="3" class="input">${escapeAttr(b.description || '')}</textarea>
          </label>
          <div class="dfd-field">
            <span>Contains (${(b.contains || []).length})</span>
            <div class="dfd-checkbox-list">
              ${system.components.map(c => `
                <label>
                  <input type="checkbox" data-comp-id="${c.id}" ${(b.contains || []).includes(c.id) ? 'checked' : ''}>
                  <span>${escapeAttr(c.name || c.id)}</span>
                </label>
              `).join('')}
            </div>
          </div>
          ${opts.readOnly ? '' : `
            <button data-act="delete" class="btn btn-danger btn-sm" style="width: 100%; margin-top: 8px;">Delete boundary</button>
          `}
        </div>
      `;
      wirePanelEvents('boundary', id);
    }

    function wirePanelEvents(kind, id) {
      sidePanel.querySelectorAll('[data-field]').forEach(el => {
        el.addEventListener(el.tagName === 'SELECT' ? 'change' :
                            el.type === 'checkbox' ? 'change' : 'input', () => {
          const field = el.dataset.field;
          const val = el.type === 'checkbox' ? el.checked : el.value;
          const target = kind === 'component'
            ? system.components.find(x => x.id === id)
            : kind === 'flow'
              ? system.data_flows.find(x => x.id === id)
              : system.trust_boundaries.find(x => x.id === id);
          if (target) {
            target[field] = val;
            render();
            opts.onChange(getSystem());
            // Changing a component's type changes which security attributes apply —
            // refresh the panel so the contextual fields update.
            if (kind === 'component' && field === 'type') showComponentPanel(id);
          }
        });
      });
      // Multi-value chip toggles (flow protocol / auth arrays)
      sidePanel.querySelectorAll('.dfd-multi [data-multi-val]').forEach(btn => {
        btn.addEventListener('click', () => {
          const group = btn.closest('.dfd-multi');
          const field = group.dataset.multi;
          const target = kind === 'flow' ? system.data_flows.find(x => x.id === id) : null;
          if (!target) return;
          const arr = toArr(target[field]);
          const v = btn.dataset.multiVal;
          const i = arr.findIndex(x => String(x).toLowerCase() === v.toLowerCase());
          if (i >= 0) arr.splice(i, 1); else arr.push(v);
          target[field] = arr;
          showFlowPanel(id);              // refresh chip states
          render();
          opts.onChange(getSystem());
        });
      });
      // Boundary "contains" checkbox list
      sidePanel.querySelectorAll('[data-comp-id]').forEach(cb => {
        cb.addEventListener('change', () => {
          const cid = cb.dataset.compId;
          const b = system.trust_boundaries.find(x => x.id === id);
          if (!b) return;
          // Remove from any other boundary first (a component lives in exactly one)
          system.trust_boundaries.forEach(other => {
            if (other.id !== id) other.contains = (other.contains || []).filter(x => x !== cid);
          });
          if (cb.checked) {
            if (!b.contains.includes(cid)) b.contains.push(cid);
          } else {
            b.contains = b.contains.filter(x => x !== cid);
          }
          render();
          opts.onChange(getSystem());
        });
      });
      const closeBtn = sidePanel.querySelector('[data-act="close"]');
      if (closeBtn) closeBtn.addEventListener('click', deselect);
      const delBtn = sidePanel.querySelector('[data-act="delete"]');
      if (delBtn) delBtn.addEventListener('click', () => {
        if (kind === 'component') deleteComponent(id);
        else if (kind === 'flow') deleteFlow(id);
        else if (kind === 'boundary') deleteBoundary(id);
      });
    }

    // ----------------------------------------------------------------------
    //  Add / remove operations
    // ----------------------------------------------------------------------
    function genId(prefix) {
      return `${prefix}_${Math.random().toString(36).slice(2, 8)}`;
    }

    function findFreeSpot() {
      const taken = Object.values(system.layout || {});
      const overlaps = (x, y) => taken.some(p =>
        Math.abs(p.x - x) < COMP_W + 24 && Math.abs(p.y - y) < COMP_H + 24);
      for (let gy = 40; gy < CANVAS_H - COMP_H; gy += COMP_H + 40) {
        for (let gx = 40; gx < CANVAS_W - COMP_W; gx += COMP_W + 40) {
          if (!overlaps(gx, gy)) return { x: snap(gx), y: snap(gy) };
        }
      }
      // Fallback: cascade from top-left by count so it never stacks exactly.
      const n = Object.keys(system.layout || {}).length;
      return { x: snap(40 + (n % 8) * 20), y: snap(40 + (n % 8) * 20) };
    }

    function addComponent() {
      const id = genId('c');
      const newComp = {
        id,
        name: 'New component',
        type: 'service',
        description: '',
      };
      system.components.push(newComp);
      // Place in a visibly empty spot so the user actually sees it appear —
      // scan a grid and pick the first cell that doesn't overlap an existing box.
      system.layout[id] = findFreeSpot();
      // Add to "Application tier" by default
      const appTier = system.trust_boundaries.find(b => /application|app tier/i.test(b.name));
      if (appTier) appTier.contains.push(id);
      else {
        // Create one
        system.trust_boundaries.push({
          id: genId('b'),
          name: 'Application tier',
          contains: [id],
          description: '',
        });
      }
      render();
      selectComponent(id);
      opts.onChange(getSystem());
    }

    function deleteComponent(id) {
      if (!confirm('Delete this component? Flows touching it will also be removed.')) return;
      system.components = system.components.filter(c => c.id !== id);
      system.data_flows = system.data_flows.filter(f => f.from !== id && f.to !== id);
      delete system.layout[id];
      system.trust_boundaries.forEach(b => {
        b.contains = (b.contains || []).filter(cid => cid !== id);
      });
      system.trust_boundaries = system.trust_boundaries.filter(b => (b.contains || []).length > 0);
      deselect();
      opts.onChange(getSystem());
    }

    function startAddFlow() {
      if (system.components.length < 2) {
        alert('Need at least 2 components to draw a flow');
        return;
      }
      showBanner('Click the source component, then the destination component. Press Esc to cancel.');
      flowDrawing = { fromId: null, mouseX: 0, mouseY: 0 };
      svg.style.cursor = 'crosshair';
    }

    function completeFlow(toId) {
      if (!flowDrawing) return;
      if (!flowDrawing.fromId) {
        flowDrawing.fromId = toId;
        showBanner('Now click the destination component.');
        return;
      }
      if (flowDrawing.fromId === toId) {
        cancelFlowDrawing();
        return;
      }
      const from = flowDrawing.fromId;
      cancelFlowDrawing();
      createFlow(from, toId);
    }

    // Create a flow between two components (shared by click-to-connect, drag-to-connect).
    function createFlow(fromId, toId) {
      const newFlow = {
        id: genId('f'), from: fromId, to: toId,
        label: 'Data', protocol: 'HTTPS', auth: '', encrypted: true,
      };
      system.data_flows.push(newFlow);
      render();
      selectFlow(newFlow.id);
      opts.onChange(getSystem());
    }

    // Which component's box contains a canvas-space point (for drag-to-connect release).
    function componentAt(cp) {
      for (const c of (system.components || [])) {
        const p = system.layout[c.id];
        if (p && cp.x >= p.x && cp.x <= p.x + COMP_W && cp.y >= p.y && cp.y <= p.y + COMP_H) {
          return c.id;
        }
      }
      return null;
    }

    // Drag from a component's connect handle to another component to create a flow.
    function startConnectDrag(e, fromId) {
      if (opts.readOnly) return;
      e.stopPropagation();          // don't also start a reposition drag
      e.preventDefault();
      flowDrawing = { fromId, mouseX: 0, mouseY: 0 };
      svg.style.cursor = 'crosshair';
      showBanner('Release on the destination component to connect. Press Esc to cancel.');
      const move = (ev) => {
        const cp = clientToCanvas(ev);
        flowDrawing.mouseX = cp.x;
        flowDrawing.mouseY = cp.y;
        render();
      };
      const up = (ev) => {
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
        const target = componentAt(clientToCanvas(ev));
        const from = flowDrawing && flowDrawing.fromId;
        cancelFlowDrawing();
        if (from && target && target !== from) createFlow(from, target);
      };
      window.addEventListener('pointermove', move);
      window.addEventListener('pointerup', up);
    }

    function cancelFlowDrawing() {
      flowDrawing = null;
      svg.style.cursor = '';
      hideBanner();
      render();
    }

    function deleteFlow(id) {
      if (!confirm('Delete this data flow?')) return;
      system.data_flows = system.data_flows.filter(f => f.id !== id);
      deselect();
      opts.onChange(getSystem());
    }

    function addBoundary() {
      const id = genId('b');
      system.trust_boundaries.push({
        id,
        name: 'New boundary',
        contains: [],
        description: '',
      });
      render();
      selectBoundary(id);
      opts.onChange(getSystem());
    }

    function deleteBoundary(id) {
      if (!confirm('Delete this trust boundary? Components inside will become unclassified.')) return;
      system.trust_boundaries = system.trust_boundaries.filter(b => b.id !== id);
      deselect();
      opts.onChange(getSystem());
    }

    // ----------------------------------------------------------------------
    //  Re-infer trust boundaries
    // ----------------------------------------------------------------------
    async function reinferBoundaries(useLlm) {
      showBanner(useLlm ? 'Asking AI to infer trust boundaries...' : 'Re-inferring trust boundaries...');
      try {
        const r = await Auth.fetch('/api/infer-trust-boundaries', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            system: { components: system.components, data_flows: system.data_flows },
            source_text: opts.sourceText || '',
            use_llm: useLlm,
          }),
        });
        if (!r.ok) throw new Error('Inference failed');
        const data = await r.json();
        system.trust_boundaries = data.trust_boundaries || [];
        // Layout might shift since components are now in different boundaries
        system.layout = autoLayout({ ...system, layout: {} }, layers);
        render();
        opts.onChange(getSystem());
        showBanner(`✓ Trust boundaries re-inferred (${data.mode} mode, ${system.trust_boundaries.length} boundaries)`);
        setTimeout(hideBanner, 2500);
      } catch (e) {
        showBanner('✗ Re-inference failed: ' + e.message, true);
        setTimeout(hideBanner, 3000);
      }
    }

    function autoArrange() {
      system.layout = {};
      system.layout = autoLayout(system, layers);
      render();
      opts.onChange(getSystem());
    }

    // ----------------------------------------------------------------------
    //  Banner messages
    // ----------------------------------------------------------------------
    const banner = container.querySelector('#dfd-mode-banner');
    function showBanner(msg, isError = false) {
      banner.textContent = msg;
      banner.classList.remove('hidden');
      banner.style.background = isError ? '#fef2f2' : '#eef2ff';
      banner.style.color = isError ? '#991b1b' : '#3730a3';
      banner.style.borderColor = isError ? '#fecaca' : '#c7d2fe';
    }
    function hideBanner() { banner.classList.add('hidden'); }

    // ----------------------------------------------------------------------
    //  Toolbar event wiring
    // ----------------------------------------------------------------------
    container.querySelectorAll('[data-act]').forEach(btn => {
      btn.addEventListener('click', () => {
        const act = btn.dataset.act;
        if (act === 'add-component') addComponent();
        else if (act === 'add-flow') startAddFlow();
        else if (act === 'add-boundary') addBoundary();
        else if (act === 'auto-layout') autoArrange();
        else if (act === 'reinfer-heuristic') reinferBoundaries(false);
        else if (act === 'reinfer-llm') reinferBoundaries(true);
        else if (act === 'zoom-in') zoomBy(1 / 1.2);
        else if (act === 'zoom-out') zoomBy(1.2);
        else if (act === 'fit') fitView();
        else if (act === 'help') toggleHelp();
        else if (act === 'help-close') toggleHelp(false);
      });
    });

    const ASPECT = CANVAS_W / CANVAS_H;

    function applyView() {
      svg.setAttribute('viewBox', `${view.x.toFixed(1)} ${view.y.toFixed(1)} ${view.w.toFixed(1)} ${view.h.toFixed(1)}`);
      const lbl = container.querySelector('#dfd-zoom-label');
      if (lbl) lbl.textContent = Math.round((CANVAS_W / view.w) * 100) + '%';
    }

    function zoomBy(factor) {
      const cx = view.x + view.w / 2, cy = view.y + view.h / 2;
      let w = view.w * factor;
      w = Math.max(CANVAS_W * 0.25, Math.min(CANVAS_W * 4, w));
      view.w = w; view.h = w / ASPECT;
      view.x = cx - view.w / 2; view.y = cy - view.h / 2;
      applyView();
    }

    function fitView() {
      const ps = Object.values(system.layout || {});
      if (!ps.length) { view.x = 0; view.y = 0; view.w = CANVAS_W; view.h = CANVAS_H; return applyView(); }
      const pad = 70;
      const minX = Math.min(...ps.map(p => p.x)) - pad;
      const minY = Math.min(...ps.map(p => p.y)) - pad;
      const maxX = Math.max(...ps.map(p => p.x)) + COMP_W + pad;
      const maxY = Math.max(...ps.map(p => p.y)) + COMP_H + pad;
      let w = maxX - minX, h = maxY - minY;
      if (w / h < ASPECT) w = h * ASPECT; else h = w / ASPECT;
      const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
      view.w = w; view.h = h; view.x = cx - w / 2; view.y = cy - h / 2;
      applyView();
    }

    const helpEl = container.querySelector('#dfd-help');
    function toggleHelp(force) {
      const show = force === undefined ? helpEl.classList.contains('hidden') : force;
      helpEl.classList.toggle('hidden', !show);
    }

    // Pan by dragging the empty canvas background (allowed even in read-only view).
    svg.addEventListener('pointerdown', (e) => {
      const onBackground = e.target === svg || (e.target.tagName === 'rect' && e.target.parentNode === svg);
      if (!onBackground || flowDrawing) return;
      const sx = e.clientX, sy = e.clientY, vx = view.x, vy = view.y;
      const rect = svg.getBoundingClientRect();
      const scaleX = view.w / rect.width, scaleY = view.h / rect.height;
      let panned = false;
      const move = (ev) => {
        panned = true;
        view.x = vx - (ev.clientX - sx) * scaleX;
        view.y = vy - (ev.clientY - sy) * scaleY;
        applyView();
      };
      const up = () => {
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
        if (panned) svg._suppressClick = true;
      };
      window.addEventListener('pointermove', move);
      window.addEventListener('pointerup', up);
    });

    container.querySelectorAll('[data-layer]').forEach(cb => {
      cb.addEventListener('change', () => {
        layers[cb.dataset.layer] = cb.checked;
        render();
      });
    });

    // ESC cancels flow drawing or deselects
    document.addEventListener('keydown', escHandler);
    function escHandler(e) {
      if (e.key === 'Escape') {
        if (flowDrawing) cancelFlowDrawing();
        else if (selected) deselect();
      }
    }

    // SVG-level pointermove for flow drawing (works for mouse + touch)
    svg.addEventListener('pointermove', (e) => {
      if (!flowDrawing) return;
      const cp = clientToCanvas(e);
      flowDrawing.mouseX = cp.x;
      flowDrawing.mouseY = cp.y;
      render();
    });

    // Click on empty canvas deselects (but not right after a pan drag)
    svg.addEventListener('click', (e) => {
      if (svg._suppressClick) { svg._suppressClick = false; return; }
      if (e.target === svg || e.target.tagName === 'rect' && e.target.parentNode === svg) {
        if (flowDrawing) cancelFlowDrawing();
        else { clearTrace(); deselect(); }
      }
    });

    // ----------------------------------------------------------------------
    //  Public API
    // ----------------------------------------------------------------------
    function getSystem() {
      return JSON.parse(JSON.stringify(system));
    }

    function destroy() {
      document.removeEventListener('keydown', escHandler);
      container.innerHTML = '';
    }

    // Initial paint, then fit the whole diagram into view so large models aren't
    // clipped and the user starts with everything visible.
    render();
    fitView();

    return { getSystem, destroy, render };
  }

  window.DfdEditor = { mount };
})();
