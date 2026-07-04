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
  };

  const ALL_TYPES = Object.keys(TYPE_VISUALS);

  function getVisual(type) {
    return TYPE_VISUALS[type] || { icon: '📦', color: '#64748b' };
  }

  // Default layout: simple grid arrangement when components have no positions
  function autoLayout(system, layers) {
    const components = system.components || [];
    const boundaries = system.trust_boundaries || [];
    const layout = system.layout || {};
    const need = components.filter(c => !layout[c.id]);
    if (need.length === 0) return layout;

    if (boundaries.length > 0 && layers.boundaries !== false) {
      // Place each boundary in a horizontal row, components stacked inside
      const cols = Math.min(boundaries.length, 4);
      const rows = Math.ceil(boundaries.length / cols);
      const colW = CANVAS_W / cols;
      const rowH = CANVAS_H / rows;
      boundaries.forEach((b, bi) => {
        const col = bi % cols;
        const row = Math.floor(bi / cols);
        const cx = col * colW + colW / 2;
        const cy = row * rowH + rowH / 2;
        const inside = (b.contains || []).filter(cid => need.find(c => c.id === cid));
        inside.forEach((cid, i) => {
          const offset = (i - (inside.length - 1) / 2) * (COMP_H + 16);
          layout[cid] = {
            x: snap(cx - COMP_W / 2),
            y: snap(cy + offset - COMP_H / 2),
          };
        });
      });
      // Anything still unplaced
      need.forEach((c, i) => {
        if (!layout[c.id]) {
          layout[c.id] = { x: snap(40 + (i % 6) * (COMP_W + 30)), y: snap(40 + Math.floor(i / 6) * (COMP_H + 30)) };
        }
      });
    } else {
      need.forEach((c, i) => {
        layout[c.id] = {
          x: snap(40 + (i % 6) * (COMP_W + 30)),
          y: snap(40 + Math.floor(i / 6) * (COMP_H + 30)),
        };
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

    let layers = { boundaries: true, encryption: true, labels: true };
    let selected = null;            // { kind: 'component'|'flow'|'boundary', id }
    let dragging = null;            // { id, offsetX, offsetY }
    let flowDrawing = null;         // { fromId, mouseX, mouseY }
    let zoom = 1;

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
          <label class="dfd-layer-toggle"><input type="checkbox" data-layer="labels" checked> Labels</label>
        </div>
        <div class="dfd-toolbar-spacer"></div>
        <div class="dfd-toolbar-group">
          <button data-act="zoom-out" class="btn btn-sm btn-ghost" title="Zoom out">−</button>
          <span id="dfd-zoom-label" class="text-xs text-light" style="min-width: 36px; text-align: center;">100%</span>
          <button data-act="zoom-in" class="btn btn-sm btn-ghost" title="Zoom in">+</button>
        </div>
      </div>
      <div class="dfd-mode-banner hidden" id="dfd-mode-banner"></div>
      <div class="dfd-canvas-wrap">
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

      // Data flows
      (system.data_flows || []).forEach(f => {
        const fromPos = system.layout[f.from];
        const toPos = system.layout[f.to];
        if (!fromPos || !toPos) return;

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

        // Hit area (transparent thick line)
        const hit = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        hit.setAttribute('x1', adjX1);
        hit.setAttribute('y1', adjY1);
        hit.setAttribute('x2', adjX2);
        hit.setAttribute('y2', adjY2);
        hit.setAttribute('stroke', 'transparent');
        hit.setAttribute('stroke-width', 14);
        hit.style.cursor = 'pointer';
        g.appendChild(hit);

        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', adjX1);
        line.setAttribute('y1', adjY1);
        line.setAttribute('x2', adjX2);
        line.setAttribute('y2', adjY2);
        line.setAttribute('stroke', stroke);
        line.setAttribute('stroke-width', isSelected ? 2.5 : 1.8);
        if (dash) line.setAttribute('stroke-dasharray', dash);
        line.setAttribute('marker-end', arrow);
        g.appendChild(line);

        // Encryption icon at midpoint
        if (layers.encryption) {
          const mx = (adjX1 + adjX2) / 2;
          const my = (adjY1 + adjY2) / 2;
          const icon = isEncrypted ? '🔒' : '⚠';
          const iconBg = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
          iconBg.setAttribute('cx', mx);
          iconBg.setAttribute('cy', my);
          iconBg.setAttribute('r', 9);
          iconBg.setAttribute('fill', 'white');
          iconBg.setAttribute('stroke', stroke);
          iconBg.setAttribute('stroke-width', 1);
          g.appendChild(iconBg);
          const iconText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
          iconText.setAttribute('x', mx);
          iconText.setAttribute('y', my + 4);
          iconText.setAttribute('text-anchor', 'middle');
          iconText.setAttribute('font-size', 10);
          iconText.textContent = icon;
          g.appendChild(iconText);
        }

        // Label
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
          ${layers.labels ? `
            <text x="${COMP_W / 2}" y="42" text-anchor="middle" font-size="11" font-weight="600" fill="#0f172a">
              ${escapeAttr((c.name || '').slice(0, 16))}
            </text>
            <text x="${COMP_W / 2}" y="56" text-anchor="middle" font-size="9" fill="#64748b">
              ${escapeAttr(c.type || '')}
            </text>
          ` : ''}
        `;
        componentsLayer.appendChild(g);

        if (!opts.readOnly) {
          g.addEventListener('mousedown', (e) => beginDrag(e, c.id));
          g.addEventListener('click', (e) => {
            e.stopPropagation();
            // Click without drag selects
            if (!dragging || !dragging.moved) {
              if (flowDrawing) {
                completeFlow(c.id);
              } else {
                selectComponent(c.id);
              }
            }
          });
        }
      });

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
      window.addEventListener('mousemove', onDrag);
      window.addEventListener('mouseup', endDrag);
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
      window.removeEventListener('mousemove', onDrag);
      window.removeEventListener('mouseup', endDrag);
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
      sidePanel.innerHTML = `
        <div class="dfd-panel-header">
          <div class="dfd-panel-title">Data flow</div>
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
          <label class="dfd-field">
            <span>Protocol</span>
            <input type="text" data-field="protocol" value="${escapeAttr(f.protocol || '')}" class="input" placeholder="HTTPS / TCP / WSS / etc."/>
          </label>
          <label class="dfd-field">
            <span>Auth</span>
            <input type="text" data-field="auth" value="${escapeAttr(f.auth || '')}" class="input" placeholder="bearer / mtls / none"/>
          </label>
          <label class="dfd-field-checkbox">
            <input type="checkbox" data-field="encrypted" ${f.encrypted !== false ? 'checked' : ''}>
            <span>Encrypted in transit</span>
          </label>
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
          }
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

    function addComponent() {
      const id = genId('c');
      const newComp = {
        id,
        name: 'New component',
        type: 'service',
        description: '',
      };
      system.components.push(newComp);
      // Place at center
      system.layout[id] = { x: snap(CANVAS_W / 2 - COMP_W / 2), y: snap(CANVAS_H / 2 - COMP_H / 2) };
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
      const newFlow = {
        id: genId('f'),
        from: flowDrawing.fromId,
        to: toId,
        label: 'Data',
        protocol: 'HTTPS',
        auth: '',
        encrypted: true,
      };
      system.data_flows.push(newFlow);
      cancelFlowDrawing();
      render();
      selectFlow(newFlow.id);
      opts.onChange(getSystem());
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
        else if (act === 'zoom-in') { zoom = Math.min(zoom + 0.1, 2); applyZoom(); }
        else if (act === 'zoom-out') { zoom = Math.max(zoom - 0.1, 0.4); applyZoom(); }
      });
    });

    function applyZoom() {
      svg.style.transform = `scale(${zoom})`;
      svg.style.transformOrigin = 'top left';
      const lbl = container.querySelector('#dfd-zoom-label');
      if (lbl) lbl.textContent = Math.round(zoom * 100) + '%';
    }

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

    // SVG-level mousemove for flow drawing
    svg.addEventListener('mousemove', (e) => {
      if (!flowDrawing) return;
      const cp = clientToCanvas(e);
      flowDrawing.mouseX = cp.x;
      flowDrawing.mouseY = cp.y;
      render();
    });

    // Click on empty canvas deselects
    svg.addEventListener('click', (e) => {
      if (e.target === svg || e.target.tagName === 'rect' && e.target.parentNode === svg) {
        if (flowDrawing) cancelFlowDrawing();
        else deselect();
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

    // Initial paint
    render();

    return { getSystem, destroy, render };
  }

  window.DfdEditor = { mount };
})();
