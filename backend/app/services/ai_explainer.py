import json
import http.client
from typing import Any
from urllib.parse import urlsplit

from app.core.config import settings


def _fallback_explanation(finding: dict[str, Any]) -> str:
    title = finding.get("title") or "This security finding"
    severity = str(finding.get("severity") or "unknown").lower()
    location = finding.get("file") or "the reported file"
    package = finding.get("package")
    if package:
        location = f"{location} ({package} {finding.get('installed_version') or ''})"
    return (
        f"{title} was reported with {severity} severity at {location}. "
        "Review the reported rule and affected code or dependency, assess whether the "
        "risk applies in your environment, and choose a remediation that preserves the "
        "intended behavior. This explanation is a deterministic fallback, not an AI response."
    )


def explain_finding(
    finding: dict[str, Any],
    *,
    config: Any = settings,
) -> dict[str, str]:
    fallback = _fallback_explanation(finding)
    if (
        config.ai_provider.lower() != "openai-compatible"
        or not config.ai_api_url
        or not config.ai_api_key
    ):
        return {"explanation": fallback, "source": "deterministic_fallback"}

    facts = {
        key: finding.get(key)
        for key in (
            "title",
            "severity",
            "confidence",
            "scanner",
            "rule_id",
            "file",
            "line",
            "package",
            "installed_version",
            "fixed_version",
        )
        if finding.get(key) is not None
    }
    if config.ai_include_code and finding.get("code"):
        facts["code"] = str(finding["code"])[:2000]
    payload = {
        "model": config.ai_model,
        "temperature": 0,
        "messages": [
            {
                "role": "system",
                "content": "Explain a software security finding factually. Do not claim a fix is verified. Keep the answer concise.",
            },
            {"role": "user", "content": json.dumps(facts, ensure_ascii=True)},
        ],
    }
    endpoint = urlsplit(config.ai_api_url)
    if not endpoint.hostname or endpoint.username or endpoint.password:
        return {"explanation": fallback, "source": "deterministic_fallback"}
    if endpoint.scheme == "https":
        connection_type = http.client.HTTPSConnection
    elif endpoint.scheme == "http" and endpoint.hostname in {"localhost", "127.0.0.1", "::1"}:
        connection_type = http.client.HTTPConnection
    else:
        return {"explanation": fallback, "source": "deterministic_fallback"}

    request_path = endpoint.path or "/"
    if endpoint.query:
        request_path = f"{request_path}?{endpoint.query}"
    connection = None
    try:
        connection = connection_type(endpoint.hostname, endpoint.port, timeout=config.ai_timeout_seconds)
        connection.request(
            "POST",
            request_path,
            body=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {config.ai_api_key}",
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        if response.status < 200 or response.status >= 300:
            raise ValueError("AI provider returned an unsuccessful status")
        response_body = response.read(1024 * 1024 + 1)
        if len(response_body) > 1024 * 1024:
            raise ValueError("AI provider response exceeded the size limit")
        result = json.loads(response_body)
        explanation = result["choices"][0]["message"]["content"]
        if not isinstance(explanation, str) or not explanation.strip():
            raise ValueError("AI provider returned an empty explanation")
        return {"explanation": explanation[:8000], "source": "openai-compatible"}
    except (OSError, http.client.HTTPException, TimeoutError, ValueError, KeyError, IndexError, TypeError, json.JSONDecodeError):
        return {"explanation": fallback, "source": "deterministic_fallback"}
    finally:
        if connection:
            connection.close()