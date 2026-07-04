// ==========================================================================
// Automated Threat Modeling — frontend
// ==========================================================================

const COMPONENT_TYPES = [
  "user", "external_entity", "webapp", "mobile_app", "api",
  "auth_service", "admin_panel", "database", "datastore",
  "cache", "queue", "filesystem", "config", "payment_service",
];

// Application state
const state = {
  systemName: "",
  systemDesc: "",
  components: [],
  data_flows: [],
  trust_boundaries: [],
  lastAnalysis: null,
  currentProjectId: null,
};

// ==========================================================================
// Helpers
// ==========================================================================
function uid(prefix = "x") {
  return prefix + "_" + Math.random().toString(36).slice(2, 8);
}

function toast(msg, kind = "info") {
  const div = document.createElement("div");
  div.className = `toast ${kind}`;
  div.textContent = msg;
  document.getElementById("toasts").appendChild(div);
  setTimeout(() => div.remove(), 3500);
}

async function api(method, url, body, isFile = false) {
  const opts = { method, headers: {} };
  if (body && !isFile) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  } else if (body && isFile) {
    opts.body = body;
  }
  const r = await fetch(url, opts);
  if (!r.ok) {
    let detail = `HTTP ${r.status}`;
    try { detail = (await r.json()).detail || detail; } catch {}
    throw new Error(detail);
  }
  // For file downloads, return blob
  const ct = r.headers.get("content-type") || "";
  if (ct.includes("application/pdf") || ct.includes("text/markdown")) return r.blob();
  return r.json();
}

function getSelectedMethodologies() {
  return [...document.querySelectorAll('input[name="methodology"]:checked')]
    .map((el) => el.value);
}

function getSystemName() {
  // Pull from whichever tab the user is on, falling back across tabs
  return (
    document.getElementById("builder-system-name").value.trim() ||
    document.getElementById("text-system-name").value.trim() ||
    document.getElementById("diagram-system-name").value.trim() ||
    "Untitled System"
  );
}

function getSystemDesc() {
  return (
    document.getElementById("builder-system-desc").value.trim() ||
    document.getElementById("text-input").value.trim() ||
    document.getElementById("diagram-context").value.trim() ||
    ""
  );
}

// ==========================================================================
// Tabs
// ==========================================================================
document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("tab-active"));
    btn.classList.add("tab-active");
    const tab = btn.dataset.tab;
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.add("hidden"));
    document.getElementById(`tab-${tab}`).classList.remove("hidden");
  });
});

// ==========================================================================
// Tab 1: text extraction
// ==========================================================================
document.getElementById("text-extract-btn").addEventListener("click", async () => {
  const text = document.getElementById("text-input").value.trim();
  if (!text) { toast("Enter a description first", "error"); return; }

  const btn = document.getElementById("text-extract-btn");
  const orig = btn.innerHTML;
  btn.innerHTML = '<span class="spinner"></span> Extracting...';
  btn.disabled = true;
  try {
    const result = await api("POST", "/api/extract-from-text", { text });
    state.components = result.components;
    state.data_flows = result.data_flows;
    state.trust_boundaries = result.trust_boundaries || [];
    state.systemName = document.getElementById("text-system-name").value.trim() || "Untitled System";
    state.systemDesc = text;
    document.getElementById("builder-system-name").value = state.systemName;
    document.getElementById("builder-system-desc").value = state.systemDesc;
    renderComponents();
    renderFlows();
    renderCanvas();
    // Switch to builder so user can review
    document.querySelector('.tab-btn[data-tab="builder"]').click();
    toast(`Extracted ${state.components.length} components — review and edit, then analyze`, "success");
  } catch (e) {
    toast(`Extraction failed: ${e.message}`, "error");
  } finally {
    btn.innerHTML = orig;
    btn.disabled = false;
  }
});

// ==========================================================================
// Tab 2: diagram upload
// ==========================================================================
const dropzone = document.getElementById("dropzone");
const diagramFile = document.getElementById("diagram-file");
const diagramPreview = document.getElementById("diagram-preview");
const diagramImg = document.getElementById("diagram-img");
const diagramExtractBtn = document.getElementById("diagram-extract-btn");
let pendingDiagram = null;

dropzone.addEventListener("click", () => diagramFile.click());
dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("border-brand-500"); });
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("border-brand-500"));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("border-brand-500");
  const file = e.dataTransfer.files[0];
  if (file) handleDiagramFile(file);
});
diagramFile.addEventListener("change", (e) => {
  if (e.target.files[0]) handleDiagramFile(e.target.files[0]);
});

function handleDiagramFile(file) {
  pendingDiagram = file;
  const reader = new FileReader();
  reader.onload = (e) => {
    diagramImg.src = e.target.result;
    diagramPreview.classList.remove("hidden");
  };
  reader.readAsDataURL(file);
  diagramExtractBtn.disabled = false;
}

diagramExtractBtn.addEventListener("click", async () => {
  if (!pendingDiagram) return;
  const fd = new FormData();
  fd.append("file", pendingDiagram);
  fd.append("description", document.getElementById("diagram-context").value);

  const orig = diagramExtractBtn.innerHTML;
  diagramExtractBtn.innerHTML = '<span class="spinner"></span> Analyzing diagram...';
  diagramExtractBtn.disabled = true;
  try {
    const result = await api("POST", "/api/extract-from-diagram", fd, true);
    state.components = result.components;
    state.data_flows = result.data_flows;
    state.trust_boundaries = result.trust_boundaries || [];
    state.systemName = document.getElementById("diagram-system-name").value.trim() || "Untitled System";
    state.systemDesc = document.getElementById("diagram-context").value.trim();
    document.getElementById("builder-system-name").value = state.systemName;
    document.getElementById("builder-system-desc").value = state.systemDesc;
    renderComponents();
    renderFlows();
    renderCanvas();
    document.querySelector('.tab-btn[data-tab="builder"]').click();
    let msg = `Extracted ${state.components.length} components`;
    if (result.extraction_method === "stub-fallback") msg += " (stub — please edit manually)";
    toast(msg, "success");
    if (result.note) toast(result.note, "info");
  } catch (e) {
    toast(`Extraction failed: ${e.message}`, "error");
  } finally {
    diagramExtractBtn.innerHTML = orig;
    diagramExtractBtn.disabled = false;
  }
});

// ==========================================================================
// Tab 3: component builder
// ==========================================================================
document.getElementById("add-component-btn").addEventListener("click", () => {
  state.components.push({
    id: uid("c"),
    name: `New component ${state.components.length + 1}`,
    type: "api",
    description: "",
  });
  renderComponents();
  renderCanvas();
});

document.getElementById("add-flow-btn").addEventListener("click", () => {
  if (state.components.length < 2) {
    toast("Add at least 2 components first", "error");
    return;
  }
  state.data_flows.push({
    id: uid("f"),
    from: state.components[0].id,
    to: state.components[1].id,
    label: "",
    protocol: "HTTPS",
    auth: "session",
    encrypted: true,
  });
  renderFlows();
  renderCanvas();
});

function renderComponents() {
  const list = document.getElementById("components-list");
  document.getElementById("comp-count").textContent = `(${state.components.length})`;
  if (state.components.length === 0) {
    list.innerHTML = '<p class="text-xs text-slate-400 italic">No components yet. Click "+ Component".</p>';
    return;
  }
  list.innerHTML = state.components.map((c, i) => {
    const sel = canvasState.selectedNodeId === c.id;
    return `
    <div data-comp-row="${c.id}" class="bg-white border ${sel ? 'border-brand-500 ring-1 ring-brand-200' : 'border-slate-200'} rounded p-2 space-y-1.5">
      <div class="flex items-center gap-2">
        <input type="text" data-i="${i}" data-field="name" value="${escapeHtml(c.name)}"
               class="text-sm font-medium flex-grow rounded border-slate-300 border px-2 py-1 comp-input"/>
        <button data-i="${i}" class="text-red-500 hover:text-red-700 text-xs comp-del" title="Delete">✕</button>
      </div>
      <div class="flex items-center gap-2">
        <select data-i="${i}" data-field="type" class="text-xs rounded border border-slate-300 px-1.5 py-1 comp-input flex-grow">
          ${COMPONENT_TYPES.map(t => `<option ${t === c.type ? 'selected' : ''}>${t}</option>`).join('')}
        </select>
      </div>
      <input type="text" data-i="${i}" data-field="description" value="${escapeHtml(c.description || '')}" placeholder="Description (optional)"
             class="w-full text-xs rounded border border-slate-200 px-2 py-1 comp-input"/>
    </div>`;
  }).join('');

  list.querySelectorAll('.comp-input').forEach(el => {
    el.addEventListener('change', e => {
      const i = parseInt(e.target.dataset.i);
      state.components[i][e.target.dataset.field] = e.target.value;
      renderCanvas();
      // Re-render flows in case the changed component name shows in the dropdowns
      renderFlows();
      renderBoundariesList();
    });
  });
  list.querySelectorAll('.comp-del').forEach(el => {
    el.addEventListener('click', e => {
      const i = parseInt(e.target.dataset.i);
      const removedId = state.components[i].id;
      state.components.splice(i, 1);
      // Remove flows referencing this component
      state.data_flows = state.data_flows.filter(f => f.from !== removedId && f.to !== removedId);
      // Remove from any trust boundary
      state.trust_boundaries.forEach(b => {
        b.contains = b.contains.filter(id => id !== removedId);
      });
      // Remove the canvas position
      delete canvasState.positions[removedId];
      renderComponents();
      renderFlows();
      renderBoundariesList();
      renderCanvas();
    });
  });
}

function renderFlows() {
  const list = document.getElementById("flows-list");
  document.getElementById("flow-count").textContent = `(${state.data_flows.length})`;
  if (state.data_flows.length === 0) {
    list.innerHTML = '<p class="text-xs text-slate-400 italic">No data flows yet.</p>';
    return;
  }
  list.innerHTML = state.data_flows.map((f, i) => {
    const sel = canvasState.selectedFlowId === f.id;
    const crosses = flowCrossesBoundary(f);
    const cb_badge = crosses ? '<span class="text-[10px] px-1 py-0.5 rounded bg-rose-100 text-rose-700 ml-1" title="Crosses trust boundary">⚡ cross-zone</span>' : '';
    return `
    <div data-flow-row="${f.id}" class="bg-white border ${sel ? 'border-brand-500 ring-1 ring-brand-200' : 'border-slate-200'} rounded p-2 space-y-1.5">
      <div class="flex items-center gap-1.5">
        <select data-i="${i}" data-field="from" class="text-xs rounded border border-slate-300 px-1 py-0.5 flow-input flex-grow">
          ${state.components.map(c => `<option value="${c.id}" ${c.id === f.from ? 'selected' : ''}>${escapeHtml(c.name)}</option>`).join('')}
        </select>
        <span class="text-slate-400 text-xs">→</span>
        <select data-i="${i}" data-field="to" class="text-xs rounded border border-slate-300 px-1 py-0.5 flow-input flex-grow">
          ${state.components.map(c => `<option value="${c.id}" ${c.id === f.to ? 'selected' : ''}>${escapeHtml(c.name)}</option>`).join('')}
        </select>
        <button data-i="${i}" class="text-red-500 hover:text-red-700 text-xs flow-del" title="Delete">✕</button>
      </div>
      <div class="flex items-center gap-1.5">
        <input type="text" data-i="${i}" data-field="label" value="${escapeHtml(f.label || '')}" placeholder="label"
               class="text-xs flex-grow rounded border border-slate-200 px-1.5 py-0.5 flow-input"/>
        <select data-i="${i}" data-field="protocol" class="text-xs rounded border border-slate-200 px-1 py-0.5 flow-input" title="Protocol">
          ${["HTTPS","HTTP","TCP","gRPC","SQL","AMQP","WebSocket"].map(p => `<option ${f.protocol===p?'selected':''}>${p}</option>`).join('')}
        </select>
      </div>
      <div class="flex items-center gap-1.5 text-xs">
        <select data-i="${i}" data-field="auth" class="text-xs rounded border border-slate-200 px-1 py-0.5 flow-input" title="Auth">
          <option value="">no auth</option>
          <option ${f.auth==='session'?'selected':''}>session</option>
          <option ${f.auth==='bearer'?'selected':''}>bearer</option>
          <option ${f.auth==='mtls'?'selected':''}>mtls</option>
          <option ${f.auth==='credentials'?'selected':''}>credentials</option>
        </select>
        <label class="flex items-center gap-1 text-xs" title="Encrypted in transit">
          <input type="checkbox" data-i="${i}" data-field="encrypted" ${f.encrypted ? 'checked' : ''} class="flow-input"> 🔒 encrypted
        </label>
        ${cb_badge}
      </div>
    </div>`;
  }).join('');
  list.querySelectorAll('.flow-input').forEach(el => {
    el.addEventListener('change', e => {
      const i = parseInt(e.target.dataset.i);
      const field = e.target.dataset.field;
      state.data_flows[i][field] = field === 'encrypted' ? e.target.checked : e.target.value;
      renderCanvas();
    });
  });
  list.querySelectorAll('.flow-del').forEach(el => {
    el.addEventListener('click', e => {
      const i = parseInt(e.target.dataset.i);
      state.data_flows.splice(i, 1);
      renderFlows();
      renderCanvas();
    });
  });
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

// ==========================================================================
// DFD Canvas — interactive, animated
// ==========================================================================
const CANVAS_W = 1000, CANVAS_H = 600;

const canvasState = {
  positions: {},         // component_id -> {x, y}
  animating: false,      // animations on/off
  selectedFlowId: null,
  selectedNodeId: null,
  selectedBoundaryId: null,
  lassoMode: false,
  drag: null,            // { id, dx, dy }
  lasso: null,           // { x0, y0, x1, y1 }
};

function nodeShape(type) {
  if (["database", "datastore", "cache", "filesystem", "queue", "config"].includes(type)) return "store";
  if (["user", "external_entity"].includes(type)) return "extern";
  return "process";
}

function nodeSize(shape) {
  if (shape === "store")  return { w: 140, h: 50 };
  if (shape === "extern") return { w: 130, h: 50 };
  return { w: 140, h: 56 };
}

function nodeColors(shape) {
  return ({
    process: { fill: "#ecfdf5", stroke: "#10b981", text: "#064e3b" },
    store:   { fill: "#eef2ff", stroke: "#6366f1", text: "#312e81" },
    extern:  { fill: "#eff6ff", stroke: "#3b82f6", text: "#1e3a8a" },
  })[shape];
}

const BOUNDARY_PALETTE = [
  { stroke: "#f43f5e", fill: "#fff1f2" },
  { stroke: "#a855f7", fill: "#faf5ff" },
  { stroke: "#0ea5e9", fill: "#f0f9ff" },
  { stroke: "#f59e0b", fill: "#fffbeb" },
  { stroke: "#14b8a6", fill: "#f0fdfa" },
];

// --- coordinate conversion: SVG client → SVG viewBox ---
function svgPoint(evt) {
  const svg = document.getElementById("dfd-canvas");
  const pt = svg.createSVGPoint();
  pt.x = evt.clientX; pt.y = evt.clientY;
  return pt.matrixTransform(svg.getScreenCTM().inverse());
}

// --- auto-layout via the server ---
async function autoLayoutCanvas() {
  if (state.components.length === 0) {
    canvasState.positions = {};
    renderCanvas();
    return;
  }
  try {
    const r = await api("POST", "/api/auto-layout", {
      system: serializeSystem(),
      width: CANVAS_W, height: CANVAS_H,
    });
    canvasState.positions = r.layout || {};
    renderCanvas();
  } catch (e) {
    // Fallback: simple grid
    fallbackGridLayout();
    renderCanvas();
  }
}

function fallbackGridLayout() {
  const cols = Math.min(3, Math.max(1, Math.ceil(Math.sqrt(state.components.length))));
  state.components.forEach((c, i) => {
    const col = i % cols, row = Math.floor(i / cols);
    canvasState.positions[c.id] = {
      x: 120 + col * 280,
      y: 120 + row * 160,
    };
  });
}

function ensureAllPositions() {
  // Any component without a position gets one
  let needsLayout = false;
  state.components.forEach(c => {
    if (!canvasState.positions[c.id]) needsLayout = true;
  });
  if (needsLayout) autoLayoutCanvas();
}

function serializeSystem() {
  return {
    name: state.systemName || getSystemName(),
    description: state.systemDesc || "",
    components: state.components,
    data_flows: state.data_flows.map(f => ({
      id: f.id, from: f.from, to: f.to, label: f.label,
      protocol: f.protocol, auth: f.auth, encrypted: f.encrypted,
    })),
    trust_boundaries: state.trust_boundaries,
  };
}

// --- rendering ---
function intersectRect(p, target, w, h) {
  const dx = target.x - p.x, dy = target.y - p.y;
  if (dx === 0 && dy === 0) return p;
  const halfW = w / 2, halfH = h / 2;
  if (Math.abs(dx) * halfH > Math.abs(dy) * halfW) {
    const sign = dx > 0 ? 1 : -1;
    return { x: p.x + sign * halfW, y: p.y + dy * (halfW / Math.abs(dx)) };
  }
  const sign = dy > 0 ? 1 : -1;
  return { x: p.x + dx * (halfH / Math.abs(dy)), y: p.y + sign * halfH };
}

function getCompBoundary(compId) {
  for (const b of state.trust_boundaries) {
    if (b.contains.includes(compId)) return b.id;
  }
  return null;
}

function flowCrossesBoundary(flow) {
  return getCompBoundary(flow.from) !== getCompBoundary(flow.to);
}

function renderCanvas() {
  const empty = document.getElementById("canvas-empty-state");
  empty.style.display = state.components.length === 0 ? "" : "none";

  ensureAllPositions();
  renderBoundaries();
  renderFlowsLayer();
  renderNodes();
}

function renderBoundaries() {
  const layer = document.getElementById("boundaries-layer");
  layer.innerHTML = "";
  state.trust_boundaries.forEach((b, i) => {
    const palette = BOUNDARY_PALETTE[i % BOUNDARY_PALETTE.length];
    const containedPos = b.contains.map(cid => canvasState.positions[cid]).filter(Boolean);
    if (containedPos.length === 0) return;
    const pad = 32;
    const xs = containedPos.map(p => p.x);
    const ys = containedPos.map(p => p.y);
    const x = Math.min(...xs) - 80 - pad;
    const y = Math.min(...ys) - 40 - pad;
    const w = (Math.max(...xs) - Math.min(...xs)) + 160 + 2 * pad;
    const h = (Math.max(...ys) - Math.min(...ys)) + 80 + 2 * pad;
    const sel = canvasState.selectedBoundaryId === b.id ? ' stroke-width="3"' : ' stroke-width="2"';
    const animClass = canvasState.animating ? "boundary-animated" : "";
    layer.insertAdjacentHTML("beforeend", `
      <g class="boundary-label-group" data-bid="${b.id}">
        <rect x="${x}" y="${y}" width="${w}" height="${h}" rx="14" ry="14"
              fill="${palette.fill}" fill-opacity="0.5"
              stroke="${palette.stroke}" stroke-dasharray="8,5" class="${animClass}"${sel}/>
        <rect x="${x + 10}" y="${y - 11}" rx="3" ry="3"
              width="${escapeHtml(b.name).length * 7 + 28}" height="22" fill="${palette.stroke}"/>
        <text x="${x + 19}" y="${y + 4}" font-size="11" font-weight="600" fill="white"
              style="pointer-events:none">🛡 ${escapeHtml(b.name)}</text>
        <text x="${x + w - 14}" y="${y + 16}" font-size="14" fill="${palette.stroke}"
              class="boundary-delete" data-bid-del="${b.id}" text-anchor="middle"
              style="font-weight:bold;cursor:pointer">×</text>
      </g>
    `);
  });

  // Click on label-group selects boundary; × deletes
  layer.querySelectorAll(".boundary-label-group").forEach(g => {
    g.addEventListener("click", e => {
      if (e.target.dataset.bidDel) {
        const bid = e.target.dataset.bidDel;
        if (confirm("Delete this trust boundary?")) {
          state.trust_boundaries = state.trust_boundaries.filter(b => b.id !== bid);
          renderBoundariesList();
          renderCanvas();
        }
      } else {
        canvasState.selectedBoundaryId = g.dataset.bid;
        renderBoundaries();
        // scroll boundary form into view
        document.querySelector(`[data-boundary-row="${g.dataset.bid}"]`)?.scrollIntoView({ block: "nearest", behavior: "smooth" });
      }
    });
  });
}

function renderFlowsLayer() {
  const layer = document.getElementById("flows-layer");
  layer.innerHTML = "";
  state.data_flows.forEach(flow => {
    const src = state.components.find(c => c.id === flow.from);
    const dst = state.components.find(c => c.id === flow.to);
    if (!src || !dst) return;
    const ps = canvasState.positions[src.id];
    const pd = canvasState.positions[dst.id];
    if (!ps || !pd) return;
    const sShape = nodeShape(src.type), dShape = nodeShape(dst.type);
    const sSize = nodeSize(sShape), dSize = nodeSize(dShape);
    const a = intersectRect(ps, pd, sSize.w, sSize.h);
    const b = intersectRect(pd, ps, dSize.w, dSize.h);
    const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
    const dxv = b.x - a.x, dyv = b.y - a.y;
    const length = Math.max(1, Math.hypot(dxv, dyv));
    const nx = -dyv / length, ny = dxv / length;
    const curve = Math.abs(dxv) > Math.abs(dyv) ? 14 : 10;
    const cx = mx + nx * curve, cy = my + ny * curve;

    const crosses = flowCrossesBoundary(flow);
    const encrypted = flow.encrypted !== false;
    const color = (!encrypted || crosses) ? "#ef4444" : "#64748b";
    const dash = !encrypted ? "5,4" : "0";
    const width = crosses ? 2.2 : 1.6;
    const sel = canvasState.selectedFlowId === flow.id;
    const opacity = sel ? 1 : 0.92;
    const strokeWidthFinal = sel ? width + 1 : width;

    const pathId = `path_${flow.id}`;
    const fullLabel = (flow.label || "") + (flow.protocol ? ` [${flow.protocol}]` : "");

    layer.insertAdjacentHTML("beforeend", `
      <g class="dfd-flow" data-fid="${flow.id}">
        <path id="${pathId}" d="M ${a.x},${a.y} Q ${cx},${cy} ${b.x},${b.y}"
              fill="none" stroke="${color}" stroke-width="${strokeWidthFinal}"
              stroke-dasharray="${dash}" stroke-opacity="${opacity}"
              marker-end="url(#arrow-end)" class="${crosses ? 'flow-cross-boundary' : ''}"/>
        ${canvasState.animating ? `
          <path d="M ${a.x},${a.y} Q ${cx},${cy} ${b.x},${b.y}"
                fill="none" stroke="${color}" stroke-width="${strokeWidthFinal}"
                stroke-opacity="0.55" class="flow-animated" pointer-events="none"/>
        ` : ''}
        ${fullLabel ? `
          <text font-size="10" fill="#475569" font-family="system-ui" pointer-events="none">
            <textPath href="#${pathId}" startOffset="50%" text-anchor="middle">${escapeHtml(fullLabel)}</textPath>
          </text>` : ''}
        <text x="${cx}" y="${cy + 4}" text-anchor="middle" font-size="11" fill="${color}" pointer-events="none">${encrypted ? '🔒' : '⚠'}</text>
        <!-- Wider invisible hit area -->
        <path d="M ${a.x},${a.y} Q ${cx},${cy} ${b.x},${b.y}" fill="none" stroke="transparent" stroke-width="14"/>
      </g>
    `);
  });

  layer.querySelectorAll(".dfd-flow").forEach(g => {
    g.addEventListener("click", e => {
      e.stopPropagation();
      canvasState.selectedFlowId = g.dataset.fid;
      canvasState.selectedNodeId = null;
      canvasState.selectedBoundaryId = null;
      renderCanvas();
      // Highlight the corresponding row in the form
      document.querySelector(`[data-flow-row="${g.dataset.fid}"]`)?.scrollIntoView({ block: "nearest", behavior: "smooth" });
      // Particles burst at click
      emitParticles(svgPoint(e), 8, "#ef4444");
    });
  });
}

function renderNodes() {
  const layer = document.getElementById("nodes-layer");
  layer.innerHTML = "";
  state.components.forEach(c => {
    const p = canvasState.positions[c.id];
    if (!p) return;
    const shape = nodeShape(c.type);
    const { w, h } = nodeSize(shape);
    const colors = nodeColors(shape);
    const x = p.x - w / 2, y = p.y - h / 2;
    const isSel = canvasState.selectedNodeId === c.id;
    const name = c.name.length > 18 ? c.name.slice(0, 17) + "…" : c.name;

    let shapeSvg = "";
    if (shape === "process") {
      shapeSvg = `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="10" ry="10"
                        fill="${colors.fill}" stroke="${colors.stroke}" stroke-width="${isSel ? 3 : 2}"/>`;
    } else if (shape === "store") {
      shapeSvg = `
        <rect x="${x}" y="${y}" width="${w}" height="${h}" fill="${colors.fill}"/>
        <line x1="${x}" y1="${y}" x2="${x + w}" y2="${y}" stroke="${colors.stroke}" stroke-width="${isSel ? 3 : 2}"/>
        <line x1="${x}" y1="${y + h}" x2="${x + w}" y2="${y + h}" stroke="${colors.stroke}" stroke-width="${isSel ? 3 : 2}"/>`;
    } else {
      shapeSvg = `<rect x="${x}" y="${y}" width="${w}" height="${h}"
                        fill="${colors.fill}" stroke="${colors.stroke}" stroke-width="${isSel ? 3 : 2}"/>`;
    }

    layer.insertAdjacentHTML("beforeend", `
      <g class="dfd-node ${isSel ? 'selected' : ''}" data-cid="${c.id}">
        ${shapeSvg}
        <text x="${p.x}" y="${p.y - 4}" text-anchor="middle" font-size="13" font-weight="600"
              fill="${colors.text}" pointer-events="none">${escapeHtml(name)}</text>
        <text x="${p.x}" y="${p.y + 12}" text-anchor="middle" font-size="10"
              fill="${colors.text}" opacity="0.7" pointer-events="none">${c.type}</text>
      </g>
    `);
  });

  layer.querySelectorAll(".dfd-node").forEach(g => {
    g.addEventListener("mousedown", onNodeMouseDown);
    g.addEventListener("click", e => {
      e.stopPropagation();
      if (canvasState.drag) return;  // ignore click after drag
      canvasState.selectedNodeId = g.dataset.cid;
      canvasState.selectedFlowId = null;
      canvasState.selectedBoundaryId = null;
      renderCanvas();
      document.querySelector(`[data-comp-row="${g.dataset.cid}"]`)?.scrollIntoView({ block: "nearest", behavior: "smooth" });
    });
  });
}

// --- drag handling ---
function onNodeMouseDown(e) {
  if (canvasState.lassoMode) return;
  e.preventDefault();
  const g = e.currentTarget;
  const cid = g.dataset.cid;
  const p = svgPoint(e);
  const cur = canvasState.positions[cid];
  canvasState.drag = { id: cid, dx: p.x - cur.x, dy: p.y - cur.y, moved: false };
  g.classList.add("dragging");
}
document.addEventListener("mousemove", e => {
  if (canvasState.drag) {
    const p = svgPoint(e);
    canvasState.positions[canvasState.drag.id] = {
      x: Math.max(60, Math.min(CANVAS_W - 60, p.x - canvasState.drag.dx)),
      y: Math.max(40, Math.min(CANVAS_H - 40, p.y - canvasState.drag.dy)),
    };
    canvasState.drag.moved = true;
    renderBoundaries();
    renderFlowsLayer();
    // Move just the dragged node DOM (avoid full re-render flicker)
    const g = document.querySelector(`.dfd-node[data-cid="${canvasState.drag.id}"]`);
    if (g) {
      const pos = canvasState.positions[canvasState.drag.id];
      // Easiest: redraw nodes layer; tested fast enough for typical sizes
      renderNodes();
    }
  } else if (canvasState.lasso) {
    const p = svgPoint(e);
    canvasState.lasso.x1 = p.x; canvasState.lasso.y1 = p.y;
    drawLasso();
  }
});
document.addEventListener("mouseup", e => {
  if (canvasState.drag) {
    const g = document.querySelector(`.dfd-node[data-cid="${canvasState.drag.id}"]`);
    g?.classList.remove("dragging");
    // Suppress click for a tick if we actually moved
    const moved = canvasState.drag.moved;
    canvasState.drag = null;
    if (moved) {
      setTimeout(() => {}, 0); // click handler checks canvasState.drag and is already null
    }
  }
  if (canvasState.lasso) finishLasso();
});

// --- lasso for boundary creation ---
const canvas = document.getElementById("dfd-canvas");
canvas.addEventListener("mousedown", e => {
  if (!canvasState.lassoMode) {
    // Click on empty canvas clears selection
    if (e.target === canvas || e.target.tagName === "rect" && e.target.parentElement?.id === "dfd-canvas") {
      canvasState.selectedNodeId = null;
      canvasState.selectedFlowId = null;
      canvasState.selectedBoundaryId = null;
      renderCanvas();
    }
    return;
  }
  const p = svgPoint(e);
  canvasState.lasso = { x0: p.x, y0: p.y, x1: p.x, y1: p.y };
  drawLasso();
});

function drawLasso() {
  const layer = document.getElementById("lasso-layer");
  if (!canvasState.lasso) { layer.innerHTML = ""; return; }
  const { x0, y0, x1, y1 } = canvasState.lasso;
  const x = Math.min(x0, x1), y = Math.min(y0, y1);
  const w = Math.abs(x1 - x0), h = Math.abs(y1 - y0);
  layer.innerHTML = `<rect class="lasso-rect" x="${x}" y="${y}" width="${w}" height="${h}" rx="6"/>`;
}

function finishLasso() {
  const { x0, y0, x1, y1 } = canvasState.lasso;
  const xMin = Math.min(x0, x1), xMax = Math.max(x0, x1);
  const yMin = Math.min(y0, y1), yMax = Math.max(y0, y1);
  const enclosed = state.components.filter(c => {
    const p = canvasState.positions[c.id];
    return p && p.x >= xMin && p.x <= xMax && p.y >= yMin && p.y <= yMax;
  });
  canvasState.lasso = null;
  document.getElementById("lasso-layer").innerHTML = "";
  if (enclosed.length === 0) {
    toast("No components in the box", "error");
    setLassoMode(false);
    return;
  }
  const name = prompt(`Trust boundary name (${enclosed.length} components):`,
                      `Zone ${state.trust_boundaries.length + 1}`);
  if (name) {
    state.trust_boundaries.push({
      id: uid("b"),
      name,
      contains: enclosed.map(c => c.id),
    });
    renderBoundariesList();
    renderCanvas();
    toast(`Created boundary "${name}" with ${enclosed.length} components`, "success");
  }
  setLassoMode(false);
}

function setLassoMode(on) {
  canvasState.lassoMode = on;
  const c = document.getElementById("dfd-canvas");
  c.classList.toggle("lasso-active", on);
  document.getElementById("canvas-mode-label").textContent =
    on ? "🖱 Drag a box around components to create a boundary" : "Drag nodes to reposition";
  document.getElementById("lasso-btn").classList.toggle("bg-rose-100", on);
  document.getElementById("lasso-btn").classList.toggle("border-rose-400", on);
}

// --- particles ---
function emitParticles(p, count = 6, color = "#3b82f6") {
  const layer = document.getElementById("particles-layer");
  for (let i = 0; i < count; i++) {
    const angle = (Math.PI * 2 * i) / count + Math.random() * 0.5;
    const dist = 25 + Math.random() * 25;
    const dx = Math.cos(angle) * dist;
    const dy = Math.sin(angle) * dist;
    const dot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    dot.setAttribute("cx", p.x); dot.setAttribute("cy", p.y);
    dot.setAttribute("r", 2 + Math.random() * 2);
    dot.setAttribute("fill", color);
    dot.classList.add("particle");
    dot.style.setProperty("--dx", dx + "px");
    dot.style.setProperty("--dy", dy + "px");
    layer.appendChild(dot);
    setTimeout(() => dot.remove(), 950);
  }
}

// Periodic boundary-crossing particles when animating
let crossBoundaryParticleInterval = null;
function startCrossBoundaryAnimation() {
  if (crossBoundaryParticleInterval) clearInterval(crossBoundaryParticleInterval);
  if (!canvasState.animating) return;
  crossBoundaryParticleInterval = setInterval(() => {
    state.data_flows.forEach(flow => {
      if (!flowCrossesBoundary(flow)) return;
      const src = state.components.find(c => c.id === flow.from);
      const dst = state.components.find(c => c.id === flow.to);
      if (!src || !dst) return;
      const ps = canvasState.positions[src.id], pd = canvasState.positions[dst.id];
      if (!ps || !pd) return;
      const t = 0.3 + Math.random() * 0.4;
      const mx = ps.x + (pd.x - ps.x) * t, my = ps.y + (pd.y - ps.y) * t;
      emitParticles({ x: mx, y: my }, 3, "#f43f5e");
    });
  }, 1200);
}
function stopCrossBoundaryAnimation() {
  if (crossBoundaryParticleInterval) {
    clearInterval(crossBoundaryParticleInterval);
    crossBoundaryParticleInterval = null;
  }
}

// --- toolbar buttons ---
document.getElementById("auto-layout-btn").addEventListener("click", () => {
  canvasState.positions = {};
  autoLayoutCanvas();
});
document.getElementById("toggle-anim-btn").addEventListener("click", () => {
  canvasState.animating = !canvasState.animating;
  document.getElementById("toggle-anim-btn").innerHTML = canvasState.animating ? "⏸ Pause" : "▶ Animate";
  document.getElementById("toggle-anim-btn").classList.toggle("bg-emerald-100", canvasState.animating);
  renderCanvas();
  if (canvasState.animating) startCrossBoundaryAnimation();
  else stopCrossBoundaryAnimation();
});
document.getElementById("lasso-btn").addEventListener("click", () => setLassoMode(!canvasState.lassoMode));

// ==========================================================================
// Trust boundary list (form)
// ==========================================================================
document.getElementById("add-boundary-btn").addEventListener("click", () => {
  const name = prompt("Trust boundary name:", `Zone ${state.trust_boundaries.length + 1}`);
  if (!name) return;
  state.trust_boundaries.push({ id: uid("b"), name, contains: [] });
  renderBoundariesList();
  renderCanvas();
});

function renderBoundariesList() {
  const list = document.getElementById("boundaries-list");
  document.getElementById("boundary-count").textContent = `(${state.trust_boundaries.length})`;
  if (state.trust_boundaries.length === 0) {
    list.innerHTML = '<p class="text-xs text-slate-400 italic">No boundaries. Click "+ Boundary" or "Lasso" on the canvas.</p>';
    return;
  }
  const compOpts = state.components.map(c =>
    `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join("");
  list.innerHTML = state.trust_boundaries.map((b, i) => {
    const palette = BOUNDARY_PALETTE[i % BOUNDARY_PALETTE.length];
    const containedNames = b.contains
      .map(cid => state.components.find(c => c.id === cid)?.name)
      .filter(Boolean);
    return `
      <div data-boundary-row="${b.id}" class="bg-white rounded p-2 border" style="border-left:4px solid ${palette.stroke}">
        <div class="flex items-center justify-between mb-1.5">
          <input type="text" data-bi="${i}" data-bfield="name" value="${escapeHtml(b.name)}"
                 class="text-sm font-semibold flex-grow rounded border-slate-200 border px-2 py-0.5 b-input"/>
          <button data-bi="${i}" class="ml-2 text-xs text-red-600 b-del">Delete</button>
        </div>
        <div class="text-xs text-slate-500 mb-1">${containedNames.length} component(s): ${containedNames.map(escapeHtml).join(", ") || "<i>none</i>"}</div>
        <details>
          <summary class="text-xs text-brand-600 cursor-pointer">Assign components</summary>
          <div class="mt-1 max-h-32 overflow-y-auto">
            ${state.components.map(c => `
              <label class="flex items-center gap-1.5 text-xs py-0.5">
                <input type="checkbox" data-bi="${i}" data-cid="${c.id}" ${b.contains.includes(c.id) ? 'checked' : ''} class="b-assign"/>
                ${escapeHtml(c.name)} <span class="text-slate-400">(${c.type})</span>
              </label>
            `).join("")}
          </div>
        </details>
      </div>
    `;
  }).join("");

  list.querySelectorAll(".b-input").forEach(el => {
    el.addEventListener("change", e => {
      const i = parseInt(e.target.dataset.bi);
      state.trust_boundaries[i][e.target.dataset.bfield] = e.target.value;
      renderCanvas();
    });
  });
  list.querySelectorAll(".b-del").forEach(el => {
    el.addEventListener("click", e => {
      const i = parseInt(e.target.dataset.bi);
      if (confirm(`Delete boundary "${state.trust_boundaries[i].name}"?`)) {
        state.trust_boundaries.splice(i, 1);
        renderBoundariesList();
        renderCanvas();
      }
    });
  });
  list.querySelectorAll(".b-assign").forEach(el => {
    el.addEventListener("change", e => {
      const i = parseInt(e.target.dataset.bi);
      const cid = e.target.dataset.cid;
      const b = state.trust_boundaries[i];
      // Remove from any other boundary first (a component lives in at most one)
      if (e.target.checked) {
        state.trust_boundaries.forEach(otherB => {
          if (otherB.id !== b.id) {
            otherB.contains = otherB.contains.filter(x => x !== cid);
          }
        });
        if (!b.contains.includes(cid)) b.contains.push(cid);
      } else {
        b.contains = b.contains.filter(x => x !== cid);
      }
      renderBoundariesList();
      renderCanvas();
    });
  });
}

// ==========================================================================
// Step 3: Analyze
// ==========================================================================
document.getElementById("analyze-btn").addEventListener("click", async () => {
  const methodologies = getSelectedMethodologies();
  if (methodologies.length === 0) {
    toast("Pick at least one methodology", "error");
    return;
  }
  if (state.components.length === 0) {
    toast("Add at least one component", "error");
    return;
  }

  // Pull system name/desc from builder tab (canonical source)
  state.systemName = document.getElementById("builder-system-name").value.trim() || getSystemName();
  state.systemDesc = document.getElementById("builder-system-desc").value.trim() || getSystemDesc();

  const useLlm = document.getElementById("use-llm").checked;
  const btn = document.getElementById("analyze-btn");
  const orig = btn.innerHTML;
  btn.innerHTML = '<span class="spinner"></span> Analyzing...';
  btn.disabled = true;

  try {
    const payload = {
      system: {
        name: state.systemName,
        description: state.systemDesc,
        components: state.components,
        // Convert to API shape (rename `from` since JS object key is fine, but pydantic expects 'from')
        data_flows: state.data_flows.map(f => ({
          id: f.id, from: f.from, to: f.to, label: f.label,
          protocol: f.protocol, auth: f.auth, encrypted: f.encrypted,
        })),
        trust_boundaries: state.trust_boundaries,
      },
      methodologies,
      use_llm: useLlm,
      layout: canvasState.positions,
    };
    const result = await api("POST", "/api/analyze", payload);
    state.lastAnalysis = result;
    renderResults(result);
    document.getElementById("results").scrollIntoView({ behavior: "smooth" });
    toast(`Found ${result.summary.total} threats`, "success");
  } catch (e) {
    toast(`Analysis failed: ${e.message}`, "error");
  } finally {
    btn.innerHTML = orig;
    btn.disabled = false;
  }
});

// ==========================================================================
// Render results
// ==========================================================================
function renderResults(result) {
  document.getElementById("results").classList.remove("hidden");
  const sum = result.summary;
  const cbCount = result.threats.filter(t => t.cross_boundary).length;
  document.getElementById("results-meta").textContent =
    `${result.system.name} · ${result.methodologies_used.map(m => m.toUpperCase()).join(", ")} · ` +
    `${sum.rule_based} rule-based${sum.llm_enhanced ? `, ${sum.llm_enhanced} LLM-enhanced` : ""}` +
    (cbCount ? ` · ${cbCount} cross-boundary` : "");

  // Severity cards (clickable)
  const sevCards = document.getElementById("severity-cards");
  const order = ["Critical", "High", "Medium", "Low", "Info"];
  sevCards.innerHTML = order.map(sev => `
    <div class="bg-white border border-slate-200 sev-card-${sev} p-3 rounded select-none" data-sev="${sev}" onclick="window.toggleSevFilter('${sev}', this)">
      <div class="text-2xl font-bold count-up" data-target="${sum.by_severity[sev] || 0}">0</div>
      <div class="text-xs text-slate-500 uppercase tracking-wide">${sev}</div>
    </div>
  `).join('');
  // Animate counts
  sevCards.querySelectorAll('.count-up').forEach(el => {
    const target = parseInt(el.dataset.target, 10);
    if (target === 0) { el.textContent = '0'; return; }
    let cur = 0;
    const step = Math.max(1, Math.floor(target / 22));
    const iv = setInterval(() => {
      cur += step;
      if (cur >= target) { cur = target; clearInterval(iv); }
      el.textContent = cur;
    }, 28);
  });

  // Untrusted-input boundary crossings
  const untrusted = result.untrusted_crossings || [];
  const untrustedSection = document.getElementById("untrusted-section");
  if (untrusted.length === 0) {
    untrustedSection.classList.add("hidden");
    untrustedSection.innerHTML = "";
  } else {
    untrustedSection.classList.remove("hidden");
    untrustedSection.innerHTML = `
      <div class="flex items-baseline justify-between mb-2">
        <h3 class="text-sm font-semibold text-rose-900 flex items-center gap-2">
          🚧 Untrusted-Input Boundary Crossings
          <span class="text-xs px-2 py-0.5 rounded-full bg-rose-100 text-rose-700">${untrusted.length}</span>
        </h3>
        <button class="text-xs text-slate-400 hover:text-slate-600" onclick="window.toggleUntrustedDetail()">expand all</button>
      </div>
      <p class="text-xs text-slate-500 mb-3">Flows where untrusted input enters an internal trust zone — every byte here must be treated as hostile.</p>
      <div class="grid gap-2" id="untrusted-grid">
        ${untrusted.map((c, i) => `
          <div class="untrusted-card" data-uidx="${i}">
            <div class="flex items-start justify-between gap-2">
              <div class="flex-grow">
                <div class="font-semibold text-rose-900 text-sm flex items-center gap-2">
                  ${escapeHtml(c.source.name)} → ${escapeHtml(c.destination.name)}
                  ${c.highest_severity !== "None" ? `<span class="text-xs px-2 py-0.5 rounded sev-${c.highest_severity}">${c.highest_severity}</span>` : ""}
                </div>
                <div class="zone-arrow mt-1.5">
                  <strong>${escapeHtml(c.source_zone)}</strong> <span class="text-rose-500">→</span> <strong>${escapeHtml(c.destination_zone)}</strong>
                </div>
                <div class="text-xs text-slate-600 mt-1.5">
                  Flow: <em>${escapeHtml(c.label || "(unlabeled)")}</em> · Protocol: <code>${escapeHtml(c.protocol || "—")}</code> ·
                  Auth: <code>${escapeHtml(c.auth)}</code> · ${c.encrypted ? '<span class="text-emerald-700">✅ encrypted</span>' : '<span class="text-rose-700 font-medium">❌ unencrypted</span>'} ·
                  ${c.threat_count} threat${c.threat_count !== 1 ? 's' : ''}
                </div>
              </div>
              <button class="text-xs text-rose-700 hover:text-rose-900 px-2" onclick="window.toggleUntrustedReqs(${i})" data-state="closed">show requirements ▼</button>
            </div>
            <div class="untrusted-req hidden" id="untrusted-req-${i}">
              <div class="text-xs font-semibold text-rose-900 mb-1">⚠ Validation requirements at the receiver:</div>
              <ul class="text-xs text-slate-700 list-disc ml-5 space-y-0.5">
                ${(c.input_validation_requirements || []).map(r => `<li>${escapeHtml(r)}</li>`).join('')}
              </ul>
            </div>
          </div>
        `).join('')}
      </div>
    `;
  }

  // Filter dropdowns
  const meths = [...new Set(result.threats.map(t => t.methodology))];
  document.getElementById("filter-methodology").innerHTML =
    '<option value="">All methodologies</option>' + meths.map(m => `<option>${m}</option>`).join('');
  const comps = [...new Set(result.threats.map(t => t.component_name))];
  document.getElementById("filter-component").innerHTML =
    '<option value="">All components</option>' + comps.map(c => `<option>${escapeHtml(c)}</option>`).join('');

  applyFilters();
}

window.toggleSevFilter = function(sev, el) {
  const cur = document.getElementById("filter-severity").value;
  if (cur === sev) {
    document.getElementById("filter-severity").value = "";
    document.querySelectorAll('[data-sev]').forEach(c => c.classList.remove('active-filter'));
  } else {
    document.getElementById("filter-severity").value = sev;
    document.querySelectorAll('[data-sev]').forEach(c => c.classList.remove('active-filter'));
    el.classList.add('active-filter');
  }
  applyFilters();
};

window.toggleUntrustedReqs = function(i) {
  const el = document.getElementById(`untrusted-req-${i}`);
  const btn = document.querySelector(`[data-uidx="${i}"] button`);
  if (el.classList.contains('hidden')) {
    el.classList.remove('hidden');
    btn.textContent = 'hide requirements ▲';
  } else {
    el.classList.add('hidden');
    btn.textContent = 'show requirements ▼';
  }
};

window.toggleUntrustedDetail = function() {
  const allHidden = [...document.querySelectorAll('.untrusted-req')].every(e => e.classList.contains('hidden'));
  document.querySelectorAll('.untrusted-req').forEach(e => e.classList.toggle('hidden', !allHidden));
  document.querySelectorAll('[data-uidx] button').forEach(b => {
    b.textContent = allHidden ? 'hide requirements ▲' : 'show requirements ▼';
  });
};

window.toggleThreatCard = function(idx) {
  const card = document.querySelector(`[data-tidx="${idx}"]`);
  if (!card) return;
  card.classList.toggle('threat-card-expanded');
};

function _sevClass(sev) {
  return ({
    "Critical": "cvss-chip-Critical", "High": "cvss-chip-High",
    "Medium": "cvss-chip-Medium", "Low": "cvss-chip-Low",
    "None": "cvss-chip-None"
  })[sev] || "cvss-chip-Medium";
}

function _renderThreatCard(t, idx) {
  const cwe = t.cwe || {};
  const c31 = t.cvss31 || {};
  const c40 = t.cvss40 || {};
  const cb = t.cross_boundary;

  // Bold restoration on location
  let location = "";
  if (t.location) {
    const parts = escapeHtml(t.location).split("**");
    location = parts.map((p, i) => i % 2 === 1 ? `<strong>${p}</strong>` : p).join('')
      .replace(/`([^`]+)`/g, '<code class="bg-slate-100 px-1 py-0.5 rounded text-xs">$1</code>');
  }

  const scenarioHtml = (t.attack_scenario || []).map(s => `<li>${escapeHtml(s)}</li>`).join('');
  const mitigationsHtml = (t.specific_mitigations || []).map(m => `
    <div class="mit-row ${m.control_type || 'preventive'}">
      <span class="ctype">${escapeHtml(m.control_type || 'preventive')}</span>
      <div class="action">${escapeHtml(m.action || '')}</div>
      <div class="detail">${escapeHtml(m.detail || '')}</div>
    </div>
  `).join('');
  const refsHtml = (t.references || []).map(r =>
    `<a href="${escapeHtml(r.url)}" target="_blank" rel="noopener" class="text-blue-600 hover:underline mr-3 text-xs">${escapeHtml(r.label)} ↗</a>`
  ).join('');

  return `
    <div class="bg-white border border-slate-200 rounded-lg p-4 threat-card-${t.severity}" data-tidx="${idx}">
      <div class="flex items-start justify-between gap-3 cursor-pointer" onclick="window.toggleThreatCard(${idx})">
        <div class="flex-grow min-w-0">
          <div class="flex items-center gap-2 flex-wrap">
            <h4 class="font-semibold text-sm">${escapeHtml(t.title)}</h4>
            <span class="text-xs px-2 py-0.5 rounded sev-${t.severity}">${t.severity}</span>
            <span class="text-xs px-2 py-0.5 rounded bg-indigo-100 text-indigo-700">${escapeHtml(t.methodology.toUpperCase())}</span>
            ${cwe.id ? `<span class="cwe-chip" title="${escapeHtml(cwe.name || '')}">${escapeHtml(cwe.id)}</span>` : ''}
            ${c31.score != null ? `<span class="cvss-chip ${_sevClass(c31.severity)}"><span class="cvss-label">v3.1</span>${c31.score}</span>` : ''}
            ${c40.score != null ? `<span class="cvss-chip ${_sevClass(c40.severity)}"><span class="cvss-label">v4.0</span>${c40.score}</span>` : ''}
            ${cb ? `<span class="cb-chip" title="${escapeHtml((t.src_zone||'?') + ' → ' + (t.dst_zone||'?'))}">⚡ cross-zone</span>` : ''}
            ${t.source === 'llm-enhanced' ? '<span class="text-xs px-2 py-0.5 rounded bg-purple-100 text-purple-700">🤖 LLM</span>' : ''}
          </div>
          <p class="text-xs text-slate-500 mt-1">
            ${escapeHtml(t.category)} ·
            <strong>${escapeHtml(t.component_name)}</strong> (${t.component_type})
            ${t.dread ? ` · DREAD ${t.dread.total}/50` : ''}
          </p>
        </div>
        <span class="threat-expand-icon flex-shrink-0">▼</span>
      </div>

      <div class="threat-card-detail">
        <div class="cvss-detail-grid">
          <div class="cvss-detail">
            <div class="cvss-detail-header">
              <span class="cvss-detail-name">CVSS 3.1</span>
              <span class="cvss-detail-score ${_sevClass(c31.severity)}">${c31.score ?? '—'}</span>
            </div>
            <div class="text-xs text-slate-500">${c31.severity || '—'}</div>
            <div class="cvss-meter-bar"><div style="width:${(c31.score || 0) * 10}%;background:#dc2626"></div></div>
            <div class="cvss-detail-vector mt-1">${escapeHtml(c31.vector || '')}</div>
          </div>
          <div class="cvss-detail">
            <div class="cvss-detail-header">
              <span class="cvss-detail-name">CVSS 4.0</span>
              <span class="cvss-detail-score ${_sevClass(c40.severity)}">${c40.score ?? '—'}</span>
            </div>
            <div class="text-xs text-slate-500">${c40.severity || '—'}</div>
            <div class="cvss-meter-bar"><div style="width:${(c40.score || 0) * 10}%;background:#7c3aed"></div></div>
            <div class="cvss-detail-vector mt-1">${escapeHtml(c40.vector || '')}</div>
          </div>
        </div>

        ${cb ? `<p class="text-xs text-rose-700 mb-2"><strong>Boundary crossing:</strong> ${escapeHtml(t.src_zone || '?')} → ${escapeHtml(t.dst_zone || '?')}</p>` : ''}

        ${location ? `
          <div class="mb-2">
            <div class="text-xs font-semibold text-slate-600 uppercase tracking-wide mb-1">📍 Where the threat exists</div>
            <p class="text-sm text-slate-700">${location}</p>
          </div>` : ''}

        <div class="mb-2">
          <div class="text-xs font-semibold text-slate-600 uppercase tracking-wide mb-1">📝 Description</div>
          <p class="text-sm text-slate-700">${escapeHtml(t.description)}</p>
        </div>

        ${scenarioHtml ? `
          <div class="mb-2">
            <div class="text-xs font-semibold text-slate-600 uppercase tracking-wide mb-1">⚔️ Attack scenario</div>
            <ol class="text-sm text-slate-700 list-decimal ml-5 space-y-1">${scenarioHtml}</ol>
          </div>` : ''}

        ${mitigationsHtml ? `
          <div class="mb-2">
            <div class="text-xs font-semibold text-slate-600 uppercase tracking-wide mb-1">🛡 How to mitigate</div>
            <div>${mitigationsHtml}</div>
          </div>` : ''}

        ${refsHtml ? `
          <div class="mt-2 pt-2 border-t border-slate-100">
            <div class="text-xs font-semibold text-slate-600 uppercase tracking-wide mb-1">🔗 References</div>
            <div>${refsHtml}</div>
          </div>` : ''}
      </div>
    </div>
  `;
}

function applyFilters() {
  if (!state.lastAnalysis) return;
  const sev = document.getElementById("filter-severity").value;
  const meth = document.getElementById("filter-methodology").value;
  const comp = document.getElementById("filter-component").value;
  const search = document.getElementById("filter-search").value.toLowerCase();
  const cbOnly = document.getElementById("filter-cb-btn").dataset.active === "true";

  let threats = state.lastAnalysis.threats;
  if (sev) threats = threats.filter(t => t.severity === sev);
  if (meth) threats = threats.filter(t => t.methodology === meth);
  if (comp) threats = threats.filter(t => t.component_name === comp);
  if (cbOnly) threats = threats.filter(t => t.cross_boundary);
  if (search) threats = threats.filter(t => {
    const blob = (
      t.title + ' ' + (t.component_name || '') + ' ' + t.category + ' ' +
      (t.cwe ? t.cwe.id + ' ' + (t.cwe.name || '') : '') + ' ' +
      (t.cvss31 ? t.cvss31.vector : '')
    ).toLowerCase();
    return blob.includes(search);
  });

  const list = document.getElementById("threat-list");
  if (threats.length === 0) {
    list.innerHTML = '<p class="text-sm text-slate-400 italic text-center py-8">No threats match these filters.</p>';
    return;
  }
  list.innerHTML = threats.map((t, i) => _renderThreatCard(t, i)).join('');
}

document.getElementById("filter-cb-btn").addEventListener("click", function() {
  const active = this.dataset.active === "true";
  this.dataset.active = active ? "false" : "true";
  applyFilters();
});

document.getElementById("expand-all-btn").addEventListener("click", function() {
  const cards = document.querySelectorAll('.threat-card-Critical, .threat-card-High, .threat-card-Medium, .threat-card-Low, .threat-card-Info');
  const anyCollapsed = [...cards].some(c => !c.classList.contains('threat-card-expanded'));
  cards.forEach(c => c.classList.toggle('threat-card-expanded', anyCollapsed));
  this.textContent = anyCollapsed ? 'Collapse all' : 'Expand all';
});

["filter-severity", "filter-methodology", "filter-component", "filter-search"].forEach(id => {
  const el = document.getElementById(id);
  el.addEventListener(id === "filter-search" ? "input" : "change", applyFilters);
});

// ==========================================================================
// Downloads
// ==========================================================================
async function downloadReport(format) {
  if (!state.lastAnalysis) { toast("Run an analysis first", "error"); return; }
  try {
    const blob = await api("POST", `/api/report/${format}`, state.lastAnalysis);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const ext = format === "markdown" ? "md" : (format === "html" ? "html" : "pdf");
    a.href = url;
    a.download = `threat_model.${ext}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast(`Downloaded ${format.toUpperCase()} report`, "success");
  } catch (e) {
    toast(`Download failed: ${e.message}`, "error");
  }
}
document.getElementById("dl-md-btn").addEventListener("click", () => downloadReport("markdown"));
document.getElementById("dl-pdf-btn").addEventListener("click", () => downloadReport("pdf"));
document.getElementById("dl-html-btn").addEventListener("click", () => downloadReport("html"));

// ==========================================================================
// Projects
// ==========================================================================
document.getElementById("projects-btn").addEventListener("click", async () => {
  document.getElementById("projects-modal").classList.remove("hidden");
  const container = document.getElementById("projects-list-container");
  container.innerHTML = '<p class="text-sm text-slate-400">Loading...</p>';
  try {
    const data = await api("GET", "/api/projects");
    if (data.projects.length === 0) {
      container.innerHTML = '<p class="text-sm text-slate-400 italic">No saved projects yet.</p>';
      return;
    }
    container.innerHTML = data.projects.map(p => `
      <div class="border border-slate-200 rounded p-3 mb-2 flex items-center justify-between">
        <div>
          <div class="font-medium text-sm">${escapeHtml(p.name)}</div>
          <div class="text-xs text-slate-500">Updated ${new Date(p.updated_at + 'Z').toLocaleString()}</div>
        </div>
        <div class="flex gap-2">
          <button data-id="${p.id}" class="load-proj text-xs px-3 py-1 bg-brand-600 text-white rounded hover:bg-brand-700">Load</button>
          <button data-id="${p.id}" class="del-proj text-xs px-3 py-1 border border-red-300 text-red-600 rounded hover:bg-red-50">Delete</button>
        </div>
      </div>
    `).join('');
    container.querySelectorAll('.load-proj').forEach(b =>
      b.addEventListener('click', () => loadProject(b.dataset.id)));
    container.querySelectorAll('.del-proj').forEach(b =>
      b.addEventListener('click', () => deleteProject(b.dataset.id)));
  } catch (e) {
    container.innerHTML = `<p class="text-red-600 text-sm">Failed to load: ${e.message}</p>`;
  }
});
document.getElementById("close-projects-modal").addEventListener("click", () =>
  document.getElementById("projects-modal").classList.add("hidden"));

document.getElementById("save-project-btn").addEventListener("click", async () => {
  if (state.components.length === 0) { toast("Nothing to save", "error"); return; }
  const name = state.systemName || getSystemName();
  try {
    // Make sure the layout is captured even if no analysis has been run yet
    const lastAnalysis = state.lastAnalysis
      ? { ...state.lastAnalysis, layout: canvasState.positions }
      : { layout: canvasState.positions };
    const result = await api("POST", "/api/projects", {
      id: state.currentProjectId,
      name,
      system: {
        name,
        description: state.systemDesc,
        components: state.components,
        data_flows: state.data_flows.map(f => ({
          id: f.id, from: f.from, to: f.to, label: f.label,
          protocol: f.protocol, auth: f.auth, encrypted: f.encrypted,
        })),
        trust_boundaries: state.trust_boundaries,
      },
      last_analysis: lastAnalysis,
    });
    state.currentProjectId = result.id;
    toast(`Saved "${name}"`, "success");
  } catch (e) {
    toast(`Save failed: ${e.message}`, "error");
  }
});

async function loadProject(id) {
  try {
    const p = await api("GET", `/api/projects/${id}`);
    state.currentProjectId = p.id;
    state.systemName = p.system.name;
    state.systemDesc = p.system.description;
    state.components = p.system.components;
    state.data_flows = p.system.data_flows.map(f => ({
      id: f.id, from: f.from, to: f.to, label: f.label,
      protocol: f.protocol, auth: f.auth, encrypted: f.encrypted,
    }));
    state.trust_boundaries = p.system.trust_boundaries || [];
    state.lastAnalysis = p.last_analysis;
    // Restore layout if saved
    canvasState.positions = (p.last_analysis && p.last_analysis.layout) || {};
    document.getElementById("builder-system-name").value = state.systemName;
    document.getElementById("builder-system-desc").value = state.systemDesc;
    renderComponents();
    renderFlows();
    renderBoundariesList();
    renderCanvas();
    if (state.lastAnalysis && state.lastAnalysis.threats) renderResults(state.lastAnalysis);
    document.querySelector('.tab-btn[data-tab="builder"]').click();
    document.getElementById("projects-modal").classList.add("hidden");
    toast(`Loaded "${p.name}"`, "success");
  } catch (e) {
    toast(`Load failed: ${e.message}`, "error");
  }
}

async function deleteProject(id) {
  if (!confirm("Delete this project?")) return;
  try {
    await api("DELETE", `/api/projects/${id}`);
    document.getElementById("projects-btn").click();  // refresh list
    toast("Project deleted", "success");
  } catch (e) {
    toast(`Delete failed: ${e.message}`, "error");
  }
}

// ==========================================================================
// Init
// ==========================================================================
renderComponents();
renderFlows();
renderBoundariesList();
renderCanvas();
