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
    rule_id = str(finding.get("rule_id") or finding.get("test_id") or "").lower()
    title_lower = str(title).lower()
    if package:
        location = f"{location} ({package} {finding.get('installed_version') or ''})"
    if "eval" in rule_id or "eval" in title_lower:
        meaning = "The code dynamically evaluates text as executable code."
        exploit = "If an attacker can influence that text, they may cause the application to execute attacker-chosen expressions."
        practices = "Use a fixed parser or explicit mapping of allowed operations, and validate inputs against a strict schema."
    elif "secret" in rule_id or "gitleaks" in str(finding.get("scanner", "")).lower():
        meaning = "A value matching a credential or secret detection rule was found in the repository."
        exploit = "If the value is active and exposed, another party may use it to access the associated service or data."
        practices = "Revoke and rotate the credential, load secrets from a managed secret store, and keep them out of source history."
    elif package:
        meaning = "The reported dependency version is associated with a known vulnerability."
        exploit = "An attacker may trigger the vulnerable dependency behavior through an exposed application path, depending on reachability and configuration."
        practices = "Upgrade to a scanner-reported fixed release, regenerate the lockfile, and test compatibility."
    elif "sql" in rule_id or "injection" in title_lower:
        meaning = "Untrusted input may be interpreted as part of a command or query."
        exploit = "An attacker may alter the intended operation by supplying specially formed input."
        practices = "Use parameterized APIs, keep data separate from executable query text, and validate according to the expected input type."
    else:
        meaning = "A scanner rule identified a code pattern that can create a security weakness."
        exploit = "Exploitability depends on whether an attacker can reach the code and control relevant inputs or state."
        practices = "Follow the scanner rule guidance, apply least privilege, validate untrusted inputs, and add a focused regression test."
    return (
        f"{title} was reported with {severity} severity at {location}. What it means: {meaning} "
        f"Why it matters and potential exploitation: {exploit} "
        f"Potential impact: unauthorized code execution, data exposure, or service impact may result if the weakness is reachable; assess the actual application context. "
        f"Secure coding practices and remediation: {practices} "
        "This is a deterministic, rule-based explanation, not an AI-generated response or proof of exploitability."
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
                "content": "Explain what the vulnerability means, why it matters, plausible exploitation conditions, potential impact, secure coding practices, and remediation guidance. Do not claim a fix is verified. Clearly distinguish facts from context-dependent possibilities.",
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