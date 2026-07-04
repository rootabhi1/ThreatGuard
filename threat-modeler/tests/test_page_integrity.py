"""Live page-render test.

Boots the threat-modeler app's Jinja env (without FastAPI) and renders every
HTML template with realistic dummy context, then checks the resulting HTML for:
  - No unresolved Jinja markers ({{ }} {% %})
  - All required script src files exist
  - All linked CSS files exist
  - No obvious template errors

This catches the kind of bug that broke the user's last deployment (missing JS
files, stale class names, etc.) without needing a live server.
"""
import sys
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from jinja2 import Environment, FileSystemLoader

env = Environment(loader=FileSystemLoader(PROJECT_ROOT / "templates"), autoescape=True)

PASS = 0
FAIL = 0
FAILURES = []


def t(name, fn):
    global PASS, FAIL
    try:
        fn()
        PASS += 1
        print(f"  [PASS] {name}")
    except AssertionError as e:
        FAIL += 1
        FAILURES.append(f"{name}: {e}")
        print(f"  [FAIL] {name}: {e}")
    except Exception as e:
        FAIL += 1
        FAILURES.append(f"{name}: {type(e).__name__}: {e}")
        print(f"  [FAIL] {name}: {type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
print("\n=== Template rendering ===")
# ---------------------------------------------------------------------------
TEMPLATES_TO_RENDER = [
    "_base.html",
    "_shell.html",
    "login.html",
    "register.html",
    "admin.html",
    "dashboard.html",
    "management.html",
]


def t_template_renders():
    for tpl_name in TEMPLATES_TO_RENDER:
        try:
            tpl = env.get_template(tpl_name)
            html = tpl.render(user={"role": "admin", "email": "test@x.com", "name": "Test"})
            assert html, f"{tpl_name} rendered empty"
        except Exception as e:
            raise AssertionError(f"{tpl_name} failed to render: {e}")


t("All 7 templates compile and render", t_template_renders)


def t_no_unresolved_jinja():
    """Render each, then check rendered HTML has no leftover {{ }} or {% %}."""
    for tpl_name in TEMPLATES_TO_RENDER:
        if tpl_name.startswith("_"):
            continue   # base/shell are extended, not rendered standalone
        tpl = env.get_template(tpl_name)
        html = tpl.render(user={"role": "admin", "email": "test@x.com", "name": "Test"})
        # Look for unresolved Jinja
        unresolved = re.findall(r'\{\{[^}]+\}\}|\{%[^%]+%\}', html)
        # Filter out HTML attribute placeholders that look Jinja-ish (rare)
        assert not unresolved, f"{tpl_name} has unresolved Jinja: {unresolved[:3]}"


t("Rendered pages have no unresolved {{ }} or {% %} markers", t_no_unresolved_jinja)


# ---------------------------------------------------------------------------
print("\n=== Static file references ===")
# ---------------------------------------------------------------------------
def t_all_script_srcs_exist():
    """Every <script src="/static/..."> in templates points to a real file."""
    static_root = PROJECT_ROOT / "static"
    missing = []
    for tpl_path in (PROJECT_ROOT / "templates").glob("*.html"):
        text = tpl_path.read_text(encoding="utf-8")
        for src in re.findall(r'<script src="(/static/[^"]+)"', text):
            file_path = PROJECT_ROOT / src.lstrip("/")
            if not file_path.exists():
                missing.append(f"{tpl_path.name} → {src}")
    assert not missing, f"Missing script files:\n  " + "\n  ".join(missing)


t("All <script src='/static/...'> point to existing files", t_all_script_srcs_exist)


def t_all_link_hrefs_exist():
    """Every <link href="/static/..."> in templates points to a real file."""
    missing = []
    for tpl_path in (PROJECT_ROOT / "templates").glob("*.html"):
        text = tpl_path.read_text(encoding="utf-8")
        for href in re.findall(r'<link[^>]+href="(/static/[^"]+)"', text):
            file_path = PROJECT_ROOT / href.lstrip("/")
            if not file_path.exists():
                missing.append(f"{tpl_path.name} → {href}")
    assert not missing, f"Missing link files:\n  " + "\n  ".join(missing)


t("All <link href='/static/...'> point to existing files", t_all_link_hrefs_exist)


# ---------------------------------------------------------------------------
print("\n=== JS sanity ===")
# ---------------------------------------------------------------------------
def t_js_files_balanced():
    """Brace and paren counts match."""
    bad = []
    for f in (PROJECT_ROOT / "static" / "js").glob("*.js"):
        text = f.read_text(encoding="utf-8")
        # Strip strings/comments to avoid false positives
        # Cheap version: just compare totals
        if text.count("{") != text.count("}"):
            bad.append(f"{f.name}: braces {text.count('{')} vs {text.count('}')}")
        if text.count("(") != text.count(")"):
            bad.append(f"{f.name}: parens {text.count('(')} vs {text.count(')')}")
    assert not bad, "Unbalanced JS:\n  " + "\n  ".join(bad)


t("All JS files have balanced braces and parens", t_js_files_balanced)


def t_js_no_old_class_names():
    """Modern JS shouldn't reference old Tailwind-era modal classes."""
    modern = ["dashboard.js", "management.js"]
    bad = []
    for name in modern:
        p = PROJECT_ROOT / "static" / "js" / name
        if not p.exists():
            continue
        text = p.read_text(encoding="utf-8")
        # Defensive search: 'fixed inset-0' was the old modal pattern
        if "fixed inset-0" in text:
            bad.append(f"{name}: still has 'fixed inset-0' (old modal class)")
        # 'modal-content' was the old card class
        if "class=\"modal-content" in text:
            bad.append(f"{name}: still has 'modal-content' class (now 'modal-card')")
    assert not bad, "Stale class refs in modern JS:\n  " + "\n  ".join(bad)


t("Modern JS files don't reference old modal class names", t_js_no_old_class_names)


# ---------------------------------------------------------------------------
print("\n=== ID consistency (template IDs match getElementById) ===")
# ---------------------------------------------------------------------------
def t_id_consistency():
    """Static getElementById calls map to IDs that exist in templates."""
    pairs = [
        ("dashboard.js", "dashboard.html"),
        ("admin.js", "admin.html"),
        ("management.js", "management.html"),
    ]
    fails = []
    for js_name, tpl_name in pairs:
        js = (PROJECT_ROOT / "static" / "js" / js_name).read_text(encoding="utf-8")
        tpl = (PROJECT_ROOT / "templates" / tpl_name).read_text(encoding="utf-8")
        tpl += (PROJECT_ROOT / "templates" / "_shell.html").read_text(encoding="utf-8")
        tpl += (PROJECT_ROOT / "templates" / "_base.html").read_text(encoding="utf-8")

        js_ids = set(re.findall(r"getElementById\(['\"]([a-zA-Z0-9_-]+)['\"]\)", js))
        tpl_ids = set(re.findall(r'\bid="([a-zA-Z0-9_-]+)"', tpl))
        # IDs created dynamically inside JS innerHTML are also valid
        js_dynamic_ids = set(re.findall(r'id="([a-zA-Z0-9_-]+)"', js))

        missing = js_ids - tpl_ids - js_dynamic_ids
        if missing:
            fails.append(f"{js_name} ↛ {tpl_name}: {sorted(missing)}")
    assert not fails, "Static getElementById without matching template IDs:\n  " + "\n  ".join(fails)


t("Static getElementById calls have matching template IDs", t_id_consistency)


# ---------------------------------------------------------------------------
print("\n=== CSS classes used by JS exist in app.css ===")
# ---------------------------------------------------------------------------
def t_css_classes_defined():
    """Critical CSS classes referenced by the JS are defined in app.css."""
    css = (PROJECT_ROOT / "static" / "css" / "app.css").read_text(encoding="utf-8")
    defined = set(re.findall(r'\.([a-zA-Z][a-zA-Z0-9_-]*)', css))

    critical = [
        # Shell & layout
        "app-shell", "sidebar", "sidebar-brand", "sidebar-nav", "sidebar-link",
        "main-area", "main-header", "main-content",
        # Components
        "btn", "btn-primary", "btn-secondary", "btn-ghost", "btn-danger", "btn-sm",
        "card", "card-hover", "input", "select",
        "modal", "modal-card", "modal-header", "modal-body", "modal-close",
        "modal-card-lg", "modal-title", "modal-subtitle",
        "stat-card", "stat-card-value", "stat-card-label",
        # Threat detail
        "threat-row", "threat-header", "threat-title", "threat-meta",
        "threat-meta-tag", "threat-detail",
        "detail-section", "detail-section-title",
        "attack-step", "attack-step-num",
        "mitigation-card", "mitigation-action", "mitigation-detail",
        "metric-box", "metric-box-label", "metric-box-value", "metric-box-detail",
        "ref-badge",
        # Severity / status
        "sev", "status",
        # Tabs
        "tabs", "tab", "tab-panel", "detail-tab-panel",
        # Tables
        "table", "table-card",
        # Empty state
        "empty-state", "empty-state-title", "empty-state-desc",
        # Animation/util
        "dots-loader", "role-badge", "progress-bar", "progress-bar-fill",
        "skeleton", "stagger", "tabular-nums",
        "text-light", "text-dim", "flex-col", "hidden",
    ]
    missing = [c for c in critical if c not in defined]
    assert not missing, f"Missing CSS classes: {missing}"


t("All critical CSS classes referenced by JS are defined", t_css_classes_defined)


# ---------------------------------------------------------------------------
print("\n=== API endpoints used by modern JS exist in app.py ===")
# ---------------------------------------------------------------------------
def t_api_endpoints_match():
    modern = ["dashboard.js", "admin.js", "management.js", "auth.js", "ui.js"]
    js_text = "\n".join(
        (PROJECT_ROOT / "static" / "js" / f).read_text(encoding="utf-8") for f in modern
    )
    api_calls = set()
    for match in re.finditer(r"['\"`](/api/[^'\"`?\s${]+)", js_text):
        url = match.group(1)
        url = re.sub(r'\$\{[^}]+\}', '{X}', url)
        # Remove trailing slash from URLs that were cut by string concatenation
        if url.endswith('/'):
            url = url.rstrip('/')
        api_calls.add(url)

    app_py = (PROJECT_ROOT / "app.py").read_text(encoding="utf-8")
    routes = set()
    for match in re.finditer(r'@app\.(get|post|put|delete|patch)\("([^"]+)"', app_py):
        path = match.group(2)
        path = re.sub(r'\{[^}]+\}', '{X}', path)
        routes.add(path)
        # Also add prefix-only version (e.g. /api/threat-models)
        # so that '/api/threat-models' matches when JS does + concat
        prefix = path.rsplit('/{X}', 1)[0]
        if prefix != path:
            routes.add(prefix)

    missing = sorted(api_calls - routes)
    assert not missing, f"API calls not in routes: {missing}"


t("All API endpoints used by modern JS exist on backend", t_api_endpoints_match)


# ---------------------------------------------------------------------------
print("\n=== Permission consistency ===")
# ---------------------------------------------------------------------------
def t_permission_consistency():
    """Permissions used in app.py route decorators all exist in PERMISSIONS set."""
    spec = __import__("importlib.util", fromlist=["x"]).spec_from_file_location(
        "perms", str(PROJECT_ROOT / "auth" / "permissions.py")
    )
    perms = __import__("importlib.util", fromlist=["x"]).module_from_spec(spec)
    spec.loader.exec_module(perms)
    PERMISSIONS = perms.PERMISSIONS

    app_py = (PROJECT_ROOT / "app.py").read_text(encoding="utf-8")
    used = set(re.findall(r'require_permission\(["\']([^"\']+)["\']\)', app_py))
    missing = used - PERMISSIONS
    assert not missing, f"app.py uses permissions not in PERMISSIONS set: {missing}"


t("All require_permission(...) calls reference defined permissions",
  t_permission_consistency)


# ---------------------------------------------------------------------------
print("\n=== Template-script load order ===")
# ---------------------------------------------------------------------------
def t_auth_loaded_before_inline_script():
    """auth.js and ui.js must load before inline scripts that reference them."""
    base = (PROJECT_ROOT / "templates" / "_base.html").read_text(encoding="utf-8")

    # Find positions of auth.js, ui.js, and {% block body %}
    auth_pos = base.find('"/static/js/auth.js"')
    ui_pos = base.find('"/static/js/ui.js"')
    body_pos = base.find("{% block body %}")

    assert auth_pos > 0, "auth.js not loaded in _base.html"
    assert ui_pos > 0, "ui.js not loaded in _base.html"
    assert auth_pos < body_pos, \
        "auth.js must load BEFORE {% block body %} (else inline scripts break)"
    assert ui_pos < body_pos, \
        "ui.js must load BEFORE {% block body %} (else inline scripts break)"


t("auth.js and ui.js loaded before {% block body %}",
  t_auth_loaded_before_inline_script)


def t_tailwind_cdn_loaded():
    """Tailwind CDN is loaded so utility classes work everywhere."""
    base = (PROJECT_ROOT / "templates" / "_base.html").read_text(encoding="utf-8")
    assert "cdn.tailwindcss.com" in base, \
        "Tailwind CDN not in _base.html — utility classes won't work"


t("Tailwind CDN is loaded in _base.html", t_tailwind_cdn_loaded)


# ---------------------------------------------------------------------------
print("\n=== Auth API surface (must define every method templates call) ===")
# ---------------------------------------------------------------------------
def t_auth_api_methods_defined():
    """Every Auth.X(...) call in templates must have a matching method in auth.js."""
    auth_js = (PROJECT_ROOT / "static" / "js" / "auth.js").read_text(encoding="utf-8")

    # Collect method names defined in auth.js — looks for "methodName(" or
    # "methodName:" inside an object literal followed by function/async function.
    defined = set(re.findall(r'\b(?:async\s+)?(\w+)\s*\([^)]*\)\s*\{', auth_js))
    # Filter out language keywords and noise
    defined -= {"if", "for", "while", "function", "switch", "catch", "constructor", "return", "throw"}

    # Find every Auth.<method>( call across templates and JS
    callers = {}
    for f in list((PROJECT_ROOT / "templates").glob("*.html")) + \
             list((PROJECT_ROOT / "static" / "js").glob("*.js")):
        text = f.read_text(encoding="utf-8")
        # Skip auth.js itself
        if f.name == "auth.js":
            continue
        for m in re.finditer(r'\bAuth\.(\w+)\s*\(', text):
            callers.setdefault(m.group(1), []).append(f.name)

    missing = []
    for method, files in callers.items():
        if method not in defined:
            missing.append(f"Auth.{method}() called by {set(files)} but not defined in auth.js")
    assert not missing, "Missing Auth methods:\n  " + "\n  ".join(missing)


t("Every Auth.X() call has a matching method in auth.js",
  t_auth_api_methods_defined)


def t_ui_api_methods_defined():
    """Every UI.X() call in templates must have a matching method in ui.js."""
    ui_js = (PROJECT_ROOT / "static" / "js" / "ui.js").read_text(encoding="utf-8")
    # Get the window.UI export object — find the property names
    m = re.search(r'window\.UI\s*=\s*\{([^}]+)\}', ui_js)
    if not m:
        return
    exported = set(re.findall(r'(\w+)\s*[,:]', m.group(1)))

    callers = {}
    for f in list((PROJECT_ROOT / "templates").glob("*.html")) + \
             list((PROJECT_ROOT / "static" / "js").glob("*.js")):
        if f.name == "ui.js":
            continue
        text = f.read_text(encoding="utf-8")
        for m in re.finditer(r'\bUI\.(\w+)\s*\(', text):
            callers.setdefault(m.group(1), []).append(f.name)

    missing = []
    for method, files in callers.items():
        if method not in exported:
            missing.append(f"UI.{method}() called by {set(files)} but not exported")
    assert not missing, "Missing UI exports:\n  " + "\n  ".join(missing)


t("Every UI.X() call has a matching method exported from ui.js",
  t_ui_api_methods_defined)


# ---------------------------------------------------------------------------
print("\n=== API request payload field-name match (Pydantic vs fetch body) ===")
# ---------------------------------------------------------------------------
def t_register_payload_matches_schema():
    """The fields posted to /api/auth/register must match RegisterRequest model."""
    register_html = (PROJECT_ROOT / "templates" / "register.html").read_text(encoding="utf-8")
    # Find body of fetch to /api/auth/register — accept multiline content
    idx = register_html.find('/api/auth/register')
    assert idx >= 0, "register.html doesn't reference /api/auth/register"
    # Look for JSON.stringify after that point
    chunk = register_html[idx:idx + 800]
    m = re.search(r"JSON\.stringify\(\s*\{(.+?)\}", chunk, re.DOTALL)
    assert m, "Could not find JSON.stringify body for /api/auth/register"
    body_text = m.group(1)
    keys = set(re.findall(r'(\w+)\s*:', body_text))

    # Pydantic model
    app_py = (PROJECT_ROOT / "app.py").read_text(encoding="utf-8")
    model_match = re.search(
        r'class RegisterRequest\(BaseModel\):\n((?:\s+\w+[^\n]*\n)+)',
        app_py
    )
    assert model_match, "Could not find RegisterRequest model"
    required_fields = set(re.findall(r'^\s+(\w+)\s*:', model_match.group(1), re.MULTILINE))

    missing = required_fields - keys
    assert not missing, \
        f"register.html doesn't send required fields: {missing} (sends: {keys})"


t("register.html payload includes all RegisterRequest fields",
  t_register_payload_matches_schema)


# ---------------------------------------------------------------------------
print("\n=== Feature creation form has target_date ===")
# ---------------------------------------------------------------------------
def t_feature_form_has_target_date():
    """User reported target_date was missing."""
    admin = (PROJECT_ROOT / "templates" / "admin.html").read_text(encoding="utf-8")
    assert 'name="target_date"' in admin, "target_date input missing from admin"
    assert 'name="status"' in admin, "feature status select missing from admin"


t("Feature creation form has target_date and status fields",
  t_feature_form_has_target_date)


def t_feature_creation_sends_target_date():
    """admin.js sends target_date when creating feature."""
    admin_js = (PROJECT_ROOT / "static" / "js" / "admin.js").read_text(encoding="utf-8")
    assert "target_date" in admin_js, "admin.js doesn't send target_date"


t("admin.js sends target_date in feature creation",
  t_feature_creation_sends_target_date)


# ---------------------------------------------------------------------------
print("\n=== Pages render visible content ===")
# ---------------------------------------------------------------------------
def t_pages_render_with_content():
    """Every page template must produce visible HTML content (not blank).
    This catches the 'extends wrong base' bug that left admin.html empty."""
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    env = Environment(
        loader=FileSystemLoader(str(PROJECT_ROOT / "templates")),
        autoescape=select_autoescape(),
    )
    ctx = {"user": {"role": "admin", "email": "a@x.com", "name": "Admin"}}
    pages = ["login.html", "register.html", "admin.html", "dashboard.html", "management.html"]
    blank = []
    for p in pages:
        html = env.get_template(p).render(**ctx)
        if "<body" not in html:
            blank.append(f"{p}: no <body>")
            continue
        body_inner = html.split("<body", 1)[1].split(">", 1)[1].split("</body", 1)[0]
        stripped = re.sub(r"<script.*?</script>", "", body_inner, flags=re.DOTALL)
        stripped = re.sub(r'<div id="toast-host"></div>', "", stripped).strip()
        if len(stripped) < 200:
            blank.append(f"{p}: only {len(stripped)} bytes of content (expected >200)")
    assert not blank, "Pages render blank or near-blank:\n  " + "\n  ".join(blank)


t("All pages render >200 bytes of visible content (not blank)",
  t_pages_render_with_content)


def t_extends_match_blocks():
    """Templates that use {% block content %} must extend _shell.html (which
    defines that block). Otherwise the content goes nowhere → blank page."""
    bad = []
    for tpl_path in (PROJECT_ROOT / "templates").glob("*.html"):
        if tpl_path.name.startswith("_"):
            continue
        text = tpl_path.read_text(encoding="utf-8")
        ext = re.search(r'{% extends "([^"]+)" %}', text)
        if not ext:
            continue
        base = ext.group(1)
        # Find blocks this template defines
        blocks = set(re.findall(r'{% block (\w+) %}', text))

        # If the template uses {% block content %}, its base must define it.
        if "content" in blocks:
            # _shell.html defines content; _base.html does not.
            if base == "_base.html":
                bad.append(
                    f"{tpl_path.name} extends _base.html but uses {{% block content %}} "
                    f"— content will go nowhere. Should extend _shell.html."
                )
    assert not bad, "Template/base mismatch:\n  " + "\n  ".join(bad)


t("Templates using {% block content %} extend _shell.html (not _base.html)",
  t_extends_match_blocks)


# ---------------------------------------------------------------------------
print("\n=== Final summary ===")
# ---------------------------------------------------------------------------
print()
print("=" * 60)
print(f"  Page integrity tests: {PASS} passed, {FAIL} failed")
print("=" * 60)
if FAIL > 0:
    print("\nFAILURES:")
    for f in FAILURES:
        print(f"  - {f}")
sys.exit(0 if FAIL == 0 else 1)
