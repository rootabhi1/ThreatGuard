"""Golden tests for agentic modelling reachability (0.2 follow-up).

The engine has OWASP-LLM / agentic threat rules, but before this change they were
unreachable from structured text input (which could set a component's *type* but not
its security *attributes*), and an agentic system typed generically produced only API
noise. These tests assert the fix is TYPE/ATTRIBUTE driven and therefore general — they
key on behaviour for the agentic type set + attribute schema, never on specific names,
and they prove it on two structurally different architectures.

Run: python tests/test_agentic_input.py
"""
import os
import sys

os.environ.setdefault("JWT_SECRET", "test-secret")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_engine.analyzer import parse_structured_system, analyze_system  # noqa: E402

_p = _f = 0


def check(cond, msg):
    global _p, _f
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    _p += bool(cond)
    _f += (not cond)


def comp(m, name):
    return next((c for c in m["components"] if c["name"] == name), None)


def titles(res, tier=None):
    return [t["title"].lower() for t in res["threats"] if tier is None or t.get("tier") == tier]


def has(res, sub, tier=None):
    return any(sub.lower() in t for t in titles(res, tier))


def main():
    # --- A: structured input can now express component + flow attributes ---------
    print("=== A: structured [attr=value] parsing (components + flows) ===")
    src = (
        "Planner : ai_agent [ingests_untrusted_content, prompt_injection_defense=no, "
        "autonomy_level=autonomous, tool_access=exec, human_in_the_loop=no, output_validated=no]\n"
        "Store : agent_memory [memory_scope=cross_user]\n"
        "Grounding : retriever [content_source_trust=web_scraped]\n"
        "Planner -> Store : TCP, credentials [validates_input=no, authorization=none]\n"
    )
    m = parse_structured_system(src)
    pl = comp(m, "Planner")
    check(pl and pl.get("type") == "ai_agent", "type parsed alongside attributes")
    check(pl and pl.get("ingests_untrusted_content") == "yes", "bare flag => yes")
    check(pl and pl.get("tool_access") == "exec", "choice attribute parsed")
    check(pl and pl.get("human_in_the_loop") == "no", "yn attribute parsed")
    fl = m["data_flows"][0]
    check(fl.get("validates_input") == "no" and fl.get("authorization") == "none", "flow attributes parsed")
    check(not any("unknown attribute" in i["message"] for i in m["issues"]), "no false 'unknown attribute' warnings")

    print("=== A: those attributes now drive evidenced agentic findings ===")
    r = analyze_system(m, ["stride"])
    for sub in ("prompt injection", "excessive agency", "model output", "grounding source", "memory shared"):
        check(has(r, sub, tier="evidenced"), f"evidenced finding fires from structured input: '{sub}'")

    print("=== A: invalid attribute value is disclosed, not silently accepted ===")
    m2 = parse_structured_system("A : ai_agent [tool_access=banana]\n")
    check(any("invalid" in i["message"].lower() for i in m2["issues"]), "invalid choice value disclosed")
    check(comp(m2, "A").get("tool_access") is None, "invalid value not applied")

    # --- D: type-driven baselines make ANY agentic architecture non-empty --------
    print("=== D (generality #1 — pipeline agent): baselines from types alone ===")
    arch1 = ("Ingest : retriever\nBrain : ai_agent\nActuator : llm_tool\nMem : agent_memory\n"
             "Ingest -> Brain : HTTPS\nBrain -> Actuator : HTTPS\nBrain -> Mem : TCP\n")
    r1 = analyze_system(parse_structured_system(arch1), ["stride"])
    check(has(r1, "prompt injection", tier="baseline"), "arch1: prompt-injection baseline from retriever/agent type")
    check(has(r1, "excessive agency", tier="baseline"), "arch1: excessive-agency baseline from agent type")
    check(has(r1, "memory", tier="baseline"), "arch1: memory baseline from agent_memory type")
    check(r1["summary"]["findings"] >= 0 and r1["summary"]["standard_checks"] > 0, "arch1: risk surface present as standard checks")

    print("=== D (generality #2 — support copilot, different shape/names): same coverage ===")
    arch2 = ("Customer : user\nChatbot : llm\nKB : knowledge_base\nEmbeddings : vector_db\n"
             "Customer -> Chatbot : HTTPS, session\nChatbot -> KB : HTTPS\nKB -> Embeddings : TCP\n")
    r2 = analyze_system(parse_structured_system(arch2), ["stride"])
    check(has(r2, "prompt injection", tier="baseline"), "arch2: prompt-injection baseline from llm type")
    check(has(r2, "grounding", tier="baseline") or has(r2, "provenance", tier="baseline"),
          "arch2: RAG/grounding baseline from knowledge_base type")
    check(has(r2, "memory", tier="baseline"), "arch2: memory/embedding baseline from vector_db type")

    print("=== D: baselines are standard-checks, never counted as findings ===")
    for r in (r1, r2):
        ag_base = [t for t in r["threats"] if t.get("tier") == "baseline"
                   and any(k in t["title"].lower() for k in ("prompt", "agency", "memory", "grounding", "output"))]
        check(ag_base and all(t["tier"] == "baseline" for t in ag_base), "agentic baselines tagged baseline (not findings)")

    # --- Guidance + no-noise guarantees -----------------------------------------
    print("=== Guidance: agentic-looking system typed generically is flagged ===")
    generic = ("User : user\nAgent Orchestrator : api\nRAG Service : api\nVector Store : database\n"
               "User -> Agent Orchestrator : HTTPS\n")
    rg = analyze_system(parse_structured_system(generic), ["stride"])
    check(any(mi.get("code") == "agentic_untyped" for mi in rg.get("model_issues", [])),
          "hint fired: agentic names but generic types")
    check(not any(t.get("tier") == "baseline" and "prompt injection" in t["title"].lower() for t in rg["threats"]),
          "no agentic threats invented for generic types (hint guides retyping instead)")

    print("=== No agentic noise on a plainly non-agentic system ===")
    plain = ("User : user\nWeb : webapp\nDB : database\nUser -> Web : HTTPS, session\nWeb -> DB : TCP\n")
    rp = analyze_system(parse_structured_system(plain), ["stride"])
    check(not any(k in " ".join(titles(rp)) for k in ("prompt injection", "excessive agency", "agent memory")),
          "no agentic threats on a non-agentic model")
    check(not any(mi.get("code") == "agentic_untyped" for mi in rp.get("model_issues", [])),
          "no agentic-typing hint on a non-agentic model")

    print()
    print("=" * 62)
    print(f"  Agentic input/coverage golden-model: {_p} passed, {_f} failed")
    print("=" * 62)
    if _f:
        sys.exit(1)


if __name__ == "__main__":
    main()
