#!/usr/bin/env python3
"""
PenTool - llm_config.py
Provider catalog, persisted LLM configuration and inference adapters.
"""

import json
import os
import time
from copy import deepcopy
from typing import Any, Dict, List

import requests
from dotenv import load_dotenv

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "llm_config.json")
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))


PROVIDER_PRESETS: Dict[str, Dict[str, Any]] = {
    "nvidia_nim": {
        "id": "nvidia_nim",
        "label": "NVIDIA NIM",
        "protocol": "openai",
        "api_base": "https://integrate.api.nvidia.com/v1",
        "requires_api_key": True,
        "api_key_url": "https://build.nvidia.com/",
        "description": "Catálogo cloud de NVIDIA con modelos Nemotron, Llama, Qwen y más.",
        "category": "cloud",
        "accent": "nvidia",
    },
    "nvidia_nim_local": {
        "id": "nvidia_nim_local",
        "label": "NVIDIA NIM local",
        "protocol": "openai",
        "api_base": "http://localhost:8001/v1",
        "requires_api_key": False,
        "description": "Contenedor NIM propio (puerto local 8001 para no colisionar con PenTool).",
        "category": "local",
        "accent": "nvidia",
    },
    "openai": {
        "id": "openai",
        "label": "OpenAI",
        "protocol": "openai",
        "api_base": "https://api.openai.com/v1",
        "requires_api_key": True,
        "description": "API oficial de OpenAI.",
        "category": "cloud",
        "accent": "openai",
    },
    "openrouter": {
        "id": "openrouter",
        "label": "OpenRouter",
        "protocol": "openai",
        "api_base": "https://openrouter.ai/api/v1",
        "requires_api_key": True,
        "description": "Gateway unificado para modelos de múltiples laboratorios.",
        "category": "gateway",
        "accent": "openrouter",
    },
    "groq": {
        "id": "groq",
        "label": "Groq",
        "protocol": "openai",
        "api_base": "https://api.groq.com/openai/v1",
        "requires_api_key": True,
        "description": "Inferencia de baja latencia compatible con OpenAI.",
        "category": "cloud",
        "accent": "groq",
    },
    "together": {
        "id": "together",
        "label": "Together AI",
        "protocol": "openai",
        "api_base": "https://api.together.ai/v1",
        "requires_api_key": True,
        "description": "Modelos abiertos servidos mediante una API compatible.",
        "category": "cloud",
        "accent": "together",
    },
    "deepseek": {
        "id": "deepseek",
        "label": "DeepSeek",
        "protocol": "openai",
        "api_base": "https://api.deepseek.com",
        "requires_api_key": True,
        "description": "Modelos DeepSeek mediante Chat Completions.",
        "category": "cloud",
        "accent": "deepseek",
    },
    "mistral": {
        "id": "mistral",
        "label": "Mistral AI",
        "protocol": "openai",
        "api_base": "https://api.mistral.ai/v1",
        "requires_api_key": True,
        "description": "API de modelos Mistral compatible con Chat Completions.",
        "category": "cloud",
        "accent": "mistral",
    },
    "lm_studio": {
        "id": "lm_studio",
        "label": "LM Studio",
        "protocol": "openai",
        "api_base": "http://localhost:1234/v1",
        "requires_api_key": False,
        "description": "Servidor local de LM Studio.",
        "category": "local",
        "accent": "local",
    },
    "vllm": {
        "id": "vllm",
        "label": "vLLM / SGLang",
        "protocol": "openai",
        "api_base": "http://localhost:8000/v1",
        "requires_api_key": False,
        "description": "Servidor de inferencia local o remoto compatible con OpenAI.",
        "category": "local",
        "accent": "local",
    },
    "ollama": {
        "id": "ollama",
        "label": "Ollama",
        "protocol": "ollama",
        "api_base": "http://localhost:11434",
        "requires_api_key": False,
        "description": "Runtime local de Ollama mediante su API nativa.",
        "category": "local",
        "accent": "ollama",
    },
    "openai_compatible": {
        "id": "openai_compatible",
        "label": "OpenAI compatible",
        "protocol": "openai",
        "api_base": "http://localhost:1234/v1",
        "requires_api_key": False,
        "description": "Cualquier endpoint personalizado que implemente Chat Completions.",
        "category": "custom",
        "accent": "custom",
    },
}

PROVIDER_ALIASES = {
    "nvidia": "nvidia_nim",
    "nim": "nvidia_nim",
    "lmstudio": "lm_studio",
    "generic": "openai_compatible",
}

DEFAULT_LLM_CONFIG: Dict[str, Any] = {
    "provider": os.getenv("LLM_PROVIDER", "openai_compatible"),
    "api_base": os.getenv("LLM_API_BASE", os.getenv("LM_STUDIO_URL", "http://localhost:1234/v1")),
    "api_key": os.getenv("LLM_API_KEY", os.getenv("LM_STUDIO_API_KEY", "")),
    "model": os.getenv("LLM_MODEL", os.getenv("LM_STUDIO_MODEL", "")),
    "attacker_ip": os.getenv("ATTACKER_IP", ""),
    "temperature": 0.7,
    "top_p": 0.9,
    "max_tokens": 8192,
    "timeout": 120,
    "api_key_header": "Authorization",
    "api_key_prefix": "Bearer",
    "chat_path": "/chat/completions",
    "models_path": "/models",
    "extra_headers": {},
    "extra_body": {},
}

PERSISTED_CONFIG_KEYS = set(DEFAULT_LLM_CONFIG)


def get_provider_presets() -> List[Dict[str, Any]]:
    """Return public provider metadata in stable display order."""
    return [deepcopy(provider) for provider in PROVIDER_PRESETS.values()]


def _provider_protocol(provider: str) -> str:
    return PROVIDER_PRESETS.get(provider, PROVIDER_PRESETS["openai_compatible"])["protocol"]


def _normalize_path(value: str, fallback: str) -> str:
    path = str(value or fallback).strip()
    if not path.startswith("/"):
        path = f"/{path}"
    return path.rstrip("/")


def _normalize_openai_base_url(api_base: str, chat_path: str, models_path: str, fallback: str) -> str:
    base = (api_base or fallback).strip().rstrip("/")
    for suffix in (
        chat_path,
        models_path,
        "/chat/completions",
        "/completions",
        "/models",
    ):
        if suffix and base.endswith(suffix):
            base = base[: -len(suffix)].rstrip("/")
            break
    return base or fallback


def _normalize_ollama_base_url(api_base: str, fallback: str) -> str:
    base = (api_base or fallback).strip().rstrip("/")
    for suffix in ("/api/chat", "/api/tags"):
        if base.endswith(suffix):
            base = base[: -len(suffix)].rstrip("/")
    return base or fallback


def _coerce_mapping(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return deepcopy(value)
    if isinstance(value, str) and value.strip():
        parsed = json.loads(value)
        if not isinstance(parsed, dict):
            raise ValueError("Expected a JSON object")
        return parsed
    return {}


def normalize_llm_config(config: Dict[str, Any]) -> Dict[str, Any]:
    merged = deepcopy(DEFAULT_LLM_CONFIG)
    merged.update({k: v for k, v in (config or {}).items() if k in PERSISTED_CONFIG_KEYS and v is not None})

    provider = str(merged.get("provider", "openai_compatible")).strip().lower()
    provider = PROVIDER_ALIASES.get(provider, provider)
    if provider not in PROVIDER_PRESETS:
        provider = "openai_compatible"
    merged["provider"] = provider

    preset = PROVIDER_PRESETS[provider]
    merged["chat_path"] = _normalize_path(merged.get("chat_path"), "/chat/completions")
    merged["models_path"] = _normalize_path(merged.get("models_path"), "/models")
    if _provider_protocol(provider) == "ollama":
        merged["api_base"] = _normalize_ollama_base_url(merged.get("api_base"), preset["api_base"])
    else:
        merged["api_base"] = _normalize_openai_base_url(
            merged.get("api_base"),
            merged["chat_path"],
            merged["models_path"],
            preset["api_base"],
        )

    merged["api_key"] = str(merged.get("api_key", "") or "")
    merged["api_key_header"] = str(merged.get("api_key_header", "Authorization") or "Authorization").strip()
    merged["api_key_prefix"] = str(merged.get("api_key_prefix", "Bearer") or "").strip()
    merged["model"] = str(merged.get("model", "") or "").strip()
    merged["attacker_ip"] = str(merged.get("attacker_ip", "") or "").strip()
    merged["temperature"] = min(max(float(merged.get("temperature", 0.7)), 0.0), 2.0)
    merged["top_p"] = min(max(float(merged.get("top_p", 0.9)), 0.0), 1.0)
    merged["max_tokens"] = min(max(int(merged.get("max_tokens", 8192)), 1), 131072)
    merged["timeout"] = min(max(int(merged.get("timeout", 120)), 5), 3600)
    merged["extra_headers"] = _coerce_mapping(merged.get("extra_headers"))
    merged["extra_body"] = _coerce_mapping(merged.get("extra_body"))
    return {key: merged[key] for key in DEFAULT_LLM_CONFIG}


def public_llm_config(config: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Return browser-safe settings without provider credentials."""
    current = normalize_llm_config(config or load_llm_config())
    public = deepcopy(current)
    public["api_key"] = ""
    public["api_key_configured"] = bool(current.get("api_key"))
    public["extra_header_names"] = sorted(current.get("extra_headers", {}).keys())
    public["extra_headers"] = {}
    public["provider_meta"] = deepcopy(PROVIDER_PRESETS[current["provider"]])
    return public


def load_llm_config() -> Dict[str, Any]:
    if not os.path.exists(CONFIG_PATH):
        return normalize_llm_config({})
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return normalize_llm_config(data)
    except Exception:
        return normalize_llm_config({})


def save_llm_config(config: Dict[str, Any]) -> Dict[str, Any]:
    normalized = normalize_llm_config(config)
    with open(CONFIG_PATH, "w", encoding="utf-8") as handle:
        json.dump(normalized, handle, indent=2)
    return normalized


def _headers_for_config(config: Dict[str, Any]) -> Dict[str, str]:
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    headers.update({str(key): str(value) for key, value in config.get("extra_headers", {}).items()})
    if config.get("api_key"):
        prefix = config.get("api_key_prefix", "").strip()
        value = f"{prefix} {config['api_key']}".strip()
        headers[config.get("api_key_header", "Authorization")] = value
    return headers


def _endpoint_url(config: Dict[str, Any], path_key: str) -> str:
    return f"{config['api_base'].rstrip('/')}/{config[path_key].lstrip('/')}"


def _ollama_models_url(config: Dict[str, Any]) -> str:
    return f"{config['api_base'].rstrip('/')}/api/tags"


def _ollama_chat_url(config: Dict[str, Any]) -> str:
    return f"{config['api_base'].rstrip('/')}/api/chat"


def list_available_models(config: Dict[str, Any] | None = None) -> List[str]:
    current = normalize_llm_config(config or load_llm_config())
    timeout = min(max(current["timeout"], 5), 60)

    if _provider_protocol(current["provider"]) == "ollama":
        response = requests.get(_ollama_models_url(current), timeout=timeout)
        response.raise_for_status()
        data = response.json()
        models = [model.get("name", "").strip() for model in data.get("models", [])]
    else:
        response = requests.get(
            _endpoint_url(current, "models_path"),
            headers=_headers_for_config(current),
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        models = [model.get("id", "").strip() for model in data.get("data", [])]
    return sorted({model for model in models if model})


def _extract_openai_content(data: Dict[str, Any]) -> str:
    choices = data.get("choices") or []
    if not choices:
        return ""
    message = choices[0].get("message") or {}
    content = message.get("content", "")
    if isinstance(content, str):
        return content.strip() or str(message.get("reasoning_content") or "").strip()
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("text"):
                parts.append(str(item["text"]))
        return "\n".join(parts).strip()
    return str(content or message.get("reasoning_content") or "").strip()


def run_llm_chat(messages: List[Dict[str, str]], config: Dict[str, Any] | None = None) -> str:
    current = normalize_llm_config(config or load_llm_config())
    if not current["model"]:
        raise ValueError("No LLM model is configured")

    if _provider_protocol(current["provider"]) == "ollama":
        payload = {
            "model": current["model"],
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": current["temperature"],
                "top_p": current["top_p"],
                "num_predict": current["max_tokens"],
            },
        }
        payload.update(current.get("extra_body", {}))
        response = requests.post(
            _ollama_chat_url(current),
            json=payload,
            timeout=current["timeout"],
        )
        response.raise_for_status()
        return response.json().get("message", {}).get("content", "").strip()

    payload = {
        "model": current["model"],
        "messages": messages,
        "stream": False,
        "temperature": current["temperature"],
        "max_tokens": current["max_tokens"],
        "top_p": current["top_p"],
    }
    payload.update(current.get("extra_body", {}))
    response = requests.post(
        _endpoint_url(current, "chat_path"),
        headers=_headers_for_config(current),
        json=payload,
        timeout=current["timeout"],
    )
    response.raise_for_status()
    return _extract_openai_content(response.json())


def probe_llm_connection(config: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Validate model discovery and a real, minimal chat completion."""
    current = normalize_llm_config(config or load_llm_config())
    started = time.perf_counter()
    models: List[str] = []
    models_error = ""
    try:
        models = list_available_models(current)
    except Exception as exc:
        models_error = str(exc)

    if not current["model"] and models:
        current["model"] = models[0]
    if not current["model"]:
        raise ValueError("No model was provided and the provider did not return a model list")

    probe_config = deepcopy(current)
    probe_config["max_tokens"] = min(current["max_tokens"], 32)
    sample = run_llm_chat(
        [
            {"role": "system", "content": "You are a connectivity probe."},
            {"role": "user", "content": "Reply with exactly: OK"},
        ],
        probe_config,
    )
    latency_ms = round((time.perf_counter() - started) * 1000)
    return {
        "status": "online",
        "provider": current["provider"],
        "provider_label": PROVIDER_PRESETS[current["provider"]]["label"],
        "protocol": _provider_protocol(current["provider"]),
        "api_base": current["api_base"],
        "model": current["model"],
        "models_count": len(models),
        "models": models,
        "models_error": models_error,
        "inference_ok": bool(sample),
        "sample": sample[:120],
        "latency_ms": latency_ms,
    }
