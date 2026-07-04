"""Unified LLM provider layer.

Every LLM-backed feature in the app goes through this module instead of importing
a vendor SDK directly. That keeps model choice in one place and lets the same
code target different providers.

Select the backend with LLM_PROVIDER:

    anthropic   (default)  ANTHROPIC_API_KEY, ANTHROPIC_MODEL, ANTHROPIC_VISION_MODEL
    openai                 OPENAI_API_KEY, OPENAI_MODEL, OPENAI_VISION_MODEL,
                           OPENAI_BASE_URL (optional)

The 'openai' backend speaks the OpenAI chat-completions protocol, so with
OPENAI_BASE_URL it also targets Azure OpenAI, Ollama, vLLM, LiteLLM, OpenRouter,
Together, Groq and any other OpenAI-compatible endpoint.

If LLM_PROVIDER is unset, the provider is auto-detected from whichever API key is
present (Anthropic first). If no key is configured, llm_available() is False and
callers fall back to the rules engine / stubs — the app stays fully functional
offline.

Public API:
    provider() -> str
    llm_available() -> bool
    complete_text(prompt, *, max_tokens=2000, system=None) -> str | None
    complete_vision(prompt, image_bytes, media_type, *, max_tokens=3000) -> str | None
    strip_fences(text) -> str

complete_* return the model's raw text (callers json.loads as needed) or None on
any failure — never raise.
"""
from __future__ import annotations

import base64
import os
import re


# ---------------------------------------------------------------------------
# Provider / model resolution
# ---------------------------------------------------------------------------
def provider() -> str:
    """Resolved provider name: explicit LLM_PROVIDER, else auto-detected."""
    p = (os.getenv("LLM_PROVIDER") or "").strip().lower()
    if p:
        return p
    if os.getenv("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.getenv("OPENAI_API_KEY"):
        return "openai"
    return "anthropic"  # default; will simply be unavailable without a key


def _api_key() -> str | None:
    return os.getenv("OPENAI_API_KEY") if provider() == "openai" else os.getenv("ANTHROPIC_API_KEY")


def llm_available() -> bool:
    """True when the selected provider has an API key configured."""
    return bool(_api_key())


def _text_model() -> str:
    if provider() == "openai":
        return os.getenv("OPENAI_MODEL", "gpt-4o")
    return os.getenv("ANTHROPIC_MODEL", "claude-opus-4-8")


def _vision_model() -> str:
    if provider() == "openai":
        return os.getenv("OPENAI_VISION_MODEL", os.getenv("OPENAI_MODEL", "gpt-4o"))
    return os.getenv("ANTHROPIC_VISION_MODEL", os.getenv("ANTHROPIC_MODEL", "claude-opus-4-8"))


def strip_fences(text: str) -> str:
    """Remove ```json ... ``` fences a model may wrap its output in."""
    if not text:
        return text
    return re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.MULTILINE).strip()


# ---------------------------------------------------------------------------
# Text completion
# ---------------------------------------------------------------------------
def complete_text(prompt: str, *, max_tokens: int = 2000, system: str | None = None) -> str | None:
    key = _api_key()
    if not key:
        return None
    try:
        if provider() == "openai":
            return _openai_text(key, prompt, max_tokens, system)
        return _anthropic_text(key, prompt, max_tokens, system)
    except Exception as e:  # never raise into callers
        print(f"[llm:{provider()}] text completion failed: {e}")
        return None


def _anthropic_text(key, prompt, max_tokens, system):
    import anthropic
    client = anthropic.Anthropic(api_key=key)
    kw = {"model": _text_model(), "max_tokens": max_tokens,
          "messages": [{"role": "user", "content": prompt}]}
    if system:
        kw["system"] = system
    resp = client.messages.create(**kw)
    return "".join(getattr(b, "text", "") for b in resp.content
                   if getattr(b, "type", "") == "text").strip()


def _openai_text(key, prompt, max_tokens, system):
    from openai import OpenAI
    client = OpenAI(api_key=key, base_url=os.getenv("OPENAI_BASE_URL") or None)
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    resp = client.chat.completions.create(
        model=_text_model(), max_tokens=max_tokens, messages=messages)
    return (resp.choices[0].message.content or "").strip()


# ---------------------------------------------------------------------------
# Vision completion
# ---------------------------------------------------------------------------
def complete_vision(prompt: str, image_bytes: bytes, media_type: str,
                    *, max_tokens: int = 3000) -> str | None:
    key = _api_key()
    if not key:
        return None
    try:
        b64 = base64.standard_b64encode(image_bytes).decode()
        if provider() == "openai":
            return _openai_vision(key, prompt, b64, media_type, max_tokens)
        return _anthropic_vision(key, prompt, b64, media_type, max_tokens)
    except Exception as e:
        print(f"[llm:{provider()}] vision completion failed: {e}")
        return None


def _anthropic_vision(key, prompt, b64, media_type, max_tokens):
    import anthropic
    client = anthropic.Anthropic(api_key=key)
    resp = client.messages.create(
        model=_vision_model(), max_tokens=max_tokens,
        messages=[{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": media_type, "data": b64}},
            {"type": "text", "text": prompt},
        ]}],
    )
    return "".join(getattr(b, "text", "") for b in resp.content
                   if getattr(b, "type", "") == "text").strip()


def _openai_vision(key, prompt, b64, media_type, max_tokens):
    from openai import OpenAI
    client = OpenAI(api_key=key, base_url=os.getenv("OPENAI_BASE_URL") or None)
    resp = client.chat.completions.create(
        model=_vision_model(), max_tokens=max_tokens,
        messages=[{"role": "user", "content": [
            {"type": "text", "text": prompt},
            {"type": "image_url", "image_url": {"url": f"data:{media_type};base64,{b64}"}},
        ]}],
    )
    return (resp.choices[0].message.content or "").strip()
