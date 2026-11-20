import json
import os
import re
import signal
import shutil
import subprocess
import sys
import threading
import tempfile
from importlib.util import find_spec
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Protocol

from app.core.config import settings

MAX_SCANNER_OUTPUT = 10 * 1024 * 1024
MAX_FINDINGS = 10_000


@dataclass
class ScannerResult:
    scanner: str
    status: str
    findings: list[dict[str, Any]]
    error: str | None = None


class Scanner(Protocol):
    name: str

    def applicable(self, target: Path) -> bool: ...

    def available(self) -> bool: ...

    def scan(self, target: Path, timeout: int) -> ScannerResult: ...


def _relative_file(raw_file: str | None, target: Path) -> str:
    if not raw_file:
        return "unknown"
    candidate = Path(raw_file)
    if not candidate.is_absolute():
        candidate = target / candidate
    try:
        return candidate.resolve().relative_to(target).as_posix()
    except (OSError, ValueError):
        return Path(raw_file).name


def _finding(
    *,
    scanner: str,
    title: str,
    severity: str = "UNKNOWN",
    confidence: str = "UNKNOWN",
    file: str = "unknown",
    line: int = 1,
    rule_id: str | None = None,
    code: str = "",
    package: str | None = None,
    installed_version: str | None = None,
    fixed_version: str | None = None,
    references: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "title": title[:2000],
        "severity": severity.upper(),
        "confidence": confidence.upper(),
        "file": file[:2000],
        "line": max(1, line),
        "test_id": (rule_id or scanner).strip()[:255],
        "code": code[:8000],
        "scanner": scanner,
        "rule_id": rule_id,
        "package": package,
        "installed_version": installed_version,
        "fixed_version": fixed_version,
        "references": references or [],
        "metadata": metadata or {},
    }


def _run(
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    scanner_path = str(Path.home() / ".local" / "bin")
    env = {
        "PATH": os.pathsep.join(part for part in (os.environ.get("PATH", ""), scanner_path) if part),
        "HOME": str(Path.home()),
        "LANG": "C.UTF-8",
        "CI": "true",
        "NPM_CONFIG_IGNORE_SCRIPTS": "true",
        "NPM_CONFIG_AUDIT": "true",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    }
    if os.name == "nt" and os.environ.get("SYSTEMROOT"):
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]

    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=(os.name == "posix"),
        )
    except OSError as exc:
        raise RuntimeError("Scanner could not be started") from exc

    captured = [bytearray(), bytearray()]
    overflow = threading.Event()
    captured_size = 0
    capture_lock = threading.Lock()

    def terminate() -> None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except (ProcessLookupError, OSError):
            pass

    def drain(stream: Any, output: bytearray) -> None:
        nonlocal captured_size
        while chunk := stream.read(64 * 1024):
            with capture_lock:
                if captured_size + len(chunk) > MAX_SCANNER_OUTPUT:
                    overflow.set()
                elif not overflow.is_set():
                    output.extend(chunk)
                    captured_size += len(chunk)
            if overflow.is_set():
                terminate()

    readers = [
        threading.Thread(target=drain, args=(process.stdout, captured[0]), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, captured[1]), daemon=True),
    ]
    for reader in readers:
        reader.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        terminate()
        process.wait()
        for reader in readers:
            reader.join()
        raise TimeoutError("Scanner exceeded its execution time limit") from exc
    finally:
        for reader in readers:
            reader.join()
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()

    if overflow.is_set():
        raise RuntimeError("Scanner output exceeded the configured safety limit")
    return subprocess.CompletedProcess(
        command,
        process.returncode,
        captured[0].decode("utf-8", errors="replace"),
        captured[1].decode("utf-8", errors="replace"),
    )


def _json_output(result: subprocess.CompletedProcess[str]) -> Any:
    try:
        return json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise RuntimeError("Scanner returned invalid JSON") from exc


class BanditScanner:
    name = "Bandit"

    def applicable(self, target: Path) -> bool:
        return any(target.rglob("*.py"))

    def available(self) -> bool:
        return find_spec("bandit") is not None

    def scan(self, target: Path, timeout: int) -> ScannerResult:
        result = _run(
            [sys.executable, "-m", "bandit", "-r", str(target), "-f", "json", "-q"],
            cwd=target,
            timeout=timeout,
        )
        if result.returncode not in (0, 1):
            raise RuntimeError("Bandit exited with an error")
        report = _json_output(result)
        findings = [
            _finding(
                scanner=self.name,
                title=issue.get("issue_text") or "Security issue",
                severity=issue.get("issue_severity", "UNKNOWN"),
                confidence=issue.get("issue_confidence", "UNKNOWN"),
                file=_relative_file(issue.get("filename"), target),
                line=issue.get("line_number") or 1,
                rule_id=issue.get("test_id"),
                code=issue.get("code") or "",
                metadata={"test_name": issue.get("test_name")},
            )
            for issue in report.get("results", [])
        ]
        return ScannerResult(self.name, "completed", findings[:MAX_FINDINGS])


class SemgrepScanner:
    name = "Semgrep"

    def _binary(self) -> str | None:
        configured = settings.semgrep_bin or os.environ.get("SEMGREP_BIN")
        if configured:
            resolved = shutil.which(configured)
            if resolved:
                return resolved
            if Path(configured).is_file() and os.access(configured, os.X_OK):
                return str(Path(configured).resolve())
            return None
        discovered = shutil.which("semgrep")
        if discovered:
            return discovered
        pipx_default = Path.home() / ".local" / "bin" / "semgrep"
        if pipx_default.is_file() and os.access(pipx_default, os.X_OK):
            return str(pipx_default)
        return None

    def applicable(self, target: Path) -> bool:
        supported = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".c", ".h"}
        return any(path.suffix.lower() in supported for path in target.rglob("*"))

    def available(self) -> bool:
        return self._binary() is not None

    def scan(self, target: Path, timeout: int) -> ScannerResult:
        local_rules = (
            "rules:\n"
            "  - id: argus.python.security.unsafe-eval\n"
            "    languages: [python]\n"
            "    message: Avoid eval() when input may be untrusted.\n"
            "    severity: ERROR\n"
            "    pattern: eval($VALUE)\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", encoding="utf-8") as rule_file:
            rule_file.write(local_rules)
            rule_file.flush()
            result = _run(
                [
                    self._binary() or "semgrep", "scan", "--config", "p/default",
                    "--config", rule_file.name, "--json", "--metrics=off", "--quiet",
                    "--no-git-ignore", str(target),
                ],
                cwd=target,
                timeout=timeout,
            )
        if result.returncode not in (0, 1):
            raise RuntimeError("Semgrep exited with an error")
        findings = []
        for issue in _json_output(result).get("results", []):
            extra = issue.get("extra", {})
            severity = extra.get("severity", "UNKNOWN")
            findings.append(
                _finding(
                    scanner=self.name,
                    title=extra.get("message") or "Semgrep finding",
                    severity=severity,
                    confidence="HIGH",
                    file=_relative_file(issue.get("path"), target),
                    line=(issue.get("start") or {}).get("line") or 1,
                    rule_id=issue.get("check_id"),
                    code=extra.get("lines") or "",
                    metadata={"metadata": extra.get("metadata", {})},
                )
            )
        return ScannerResult(self.name, "completed", findings[:MAX_FINDINGS])


class GitleaksScanner:
    name = "Gitleaks"

    def applicable(self, target: Path) -> bool:
        return any(path.is_file() for path in target.rglob("*"))

    def available(self) -> bool:
        return shutil.which("gitleaks") is not None

    def scan(self, target: Path, timeout: int) -> ScannerResult:
        result = _run(
            ["gitleaks", "dir", "--report-format", "json", "--report-path", "/dev/stdout", str(target)],
            cwd=target,
            timeout=timeout,
        )
        if result.returncode not in (0, 1):
            raise RuntimeError("Gitleaks exited with an error")
        findings = []
        for issue in _json_output(result):
            findings.append(
                _finding(
                    scanner=self.name,
                    title=issue.get("Description") or "Potential secret detected",
                    severity="CRITICAL",
                    confidence="HIGH",
                    file=_relative_file(issue.get("File"), target),
                    line=issue.get("StartLine") or 1,
                    rule_id=issue.get("RuleID"),
                    code="[REDACTED: potential secret]",
                    references=[issue["Fingerprint"]] if issue.get("Fingerprint") else [],
                )
            )
        return ScannerResult(self.name, "completed", findings[:MAX_FINDINGS])


class PipAuditScanner:
    name = "pip-audit"
    _pinned_requirement = re.compile(
        r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9,._-]+\])?\s*==\s*[A-Za-z0-9][A-Za-z0-9.!+_-]*\s*(?:#.*)?$"
    )

    def _requirements(self, target: Path) -> Path | None:
        candidates = sorted(target.rglob("requirements.txt"))
        return candidates[0] if candidates else None

    def applicable(self, target: Path) -> bool:
        return self._requirements(target) is not None

    def available(self) -> bool:
        return shutil.which("pip-audit") is not None

    def scan(self, target: Path, timeout: int) -> ScannerResult:
        requirements = self._requirements(target)
        if requirements is None:
            return ScannerResult(self.name, "skipped", [])
        lines = requirements.read_text(encoding="utf-8").splitlines()
        if any(line.strip() and not line.lstrip().startswith("#") and not self._pinned_requirement.fullmatch(line.strip()) for line in lines):
            return ScannerResult(
                self.name,
                "failed",
                [],
                "Only pinned name==version requirements are audited; install directives and unpinned specs are rejected.",
            )
        with tempfile.TemporaryDirectory(prefix="argus-pip-audit-") as temp_dir:
            staged_requirements = Path(temp_dir) / "requirements.txt"
            staged_requirements.write_text("\n".join(lines) + "\n", encoding="utf-8")
            result = _run(
                ["pip-audit", "-r", str(staged_requirements), "--format", "json", "--no-deps"],
                cwd=Path(temp_dir),
                timeout=timeout,
            )
        if result.returncode not in (0, 1):
            raise RuntimeError("pip-audit exited with an error")
        findings = []
        for dependency in _json_output(result).get("dependencies", []):
            for vulnerability in dependency.get("vulns", []):
                fixes = vulnerability.get("fix_versions", [])
                findings.append(
                    _finding(
                        scanner=self.name,
                        title=vulnerability.get("description") or vulnerability.get("id") or "Vulnerable dependency",
                        severity="HIGH",
                        confidence="HIGH",
                        file=requirements.relative_to(target).as_posix(),
                        rule_id=vulnerability.get("id"),
                        package=dependency.get("name"),
                        installed_version=dependency.get("version"),
                        fixed_version=fixes[0] if fixes else None,
                        references=vulnerability.get("aliases", []),
                    )
                )
        return ScannerResult(self.name, "completed", findings[:MAX_FINDINGS])


class NpmAuditScanner:
    name = "npm audit"

    def _lockfile(self, target: Path) -> Path | None:
        candidates = sorted(
            path for path in target.rglob("package-lock.json")
            if (path.parent / "package.json").is_file()
        )
        return candidates[0] if candidates else None

    def applicable(self, target: Path) -> bool:
        return self._lockfile(target) is not None

    def available(self) -> bool:
        return shutil.which("npm") is not None

    def scan(self, target: Path, timeout: int) -> ScannerResult:
        lockfile = self._lockfile(target)
        if lockfile is None:
            return ScannerResult(self.name, "skipped", [])
        with tempfile.TemporaryDirectory(prefix="argus-npm-audit-") as temp_dir:
            staged = Path(temp_dir)
            shutil.copyfile(lockfile, staged / "package-lock.json")
            shutil.copyfile(lockfile.parent / "package.json", staged / "package.json")
            result = _run(
                [
                    "npm", "audit", "--json", "--ignore-scripts", "--no-fund", "--no-progress",
                    "--registry=https://registry.npmjs.org/", f"--userconfig={os.devnull}",
                    f"--globalconfig={os.devnull}",
                ],
                cwd=staged,
                timeout=timeout,
            )
        if result.returncode not in (0, 1):
            raise RuntimeError("npm audit exited with an error")
        audit = _json_output(result)
        findings = []
        for package, issue in audit.get("vulnerabilities", {}).items():
            via = issue.get("via", [])
            advisory = next((item for item in via if isinstance(item, dict)), {})
            fix = issue.get("fixAvailable")
            fixed_version = fix.get("version") if isinstance(fix, dict) else None
            findings.append(
                _finding(
                    scanner=self.name,
                    title=advisory.get("title") or f"Vulnerable npm package: {package}",
                    severity=issue.get("severity", "UNKNOWN"),
                    confidence="HIGH",
                    file=lockfile.relative_to(target).as_posix(),
                    rule_id=advisory.get("source") or package,
                    package=package,
                    installed_version=issue.get("range"),
                    fixed_version=fixed_version,
                    references=[advisory["url"]] if advisory.get("url") else [],
                )
            )
        return ScannerResult(self.name, "completed", findings[:MAX_FINDINGS])


def scan_project(
    project_path: str | Path,
    *,
    timeout: int = 120,
    include_dependency_audits: bool = True,
) -> dict[str, Any]:
    target = Path(project_path).resolve()
    if not target.exists() or not target.is_dir():
        raise ValueError("Invalid project directory")

    scanners: list[Scanner] = [BanditScanner(), SemgrepScanner(), GitleaksScanner()]
    if include_dependency_audits:
        scanners.extend((PipAuditScanner(), NpmAuditScanner()))

    results: list[ScannerResult] = []
    for scanner in scanners:
        if not scanner.applicable(target):
            results.append(ScannerResult(scanner.name, "skipped", []))
            continue
        if not scanner.available():
            results.append(ScannerResult(scanner.name, "unavailable", []))
            continue
        try:
            results.append(scanner.scan(target, timeout))
        except TimeoutError as exc:
            results.append(ScannerResult(scanner.name, "failed", [], str(exc)))
        except (RuntimeError, ValueError, OSError) as exc:
            results.append(ScannerResult(scanner.name, "failed", [], str(exc)))

    findings = []
    finding_keys = set()
    for result in results:
        for finding in result.findings:
            key = (
                finding.get("file"),
                finding.get("line"),
                finding.get("rule_id") or finding.get("test_id"),
                finding.get("title"),
            )
            if key not in finding_keys:
                finding_keys.add(key)
                findings.append(finding)
    completed = sum(result.status == "completed" for result in results)
    partial = any(result.status in ("unavailable", "failed") for result in results)
    status = "failed" if completed == 0 else "partial" if partial else "completed"
    return {
        "scanner": ", ".join(result.scanner for result in results if result.status == "completed") or "None",
        "status": status,
        "total_findings": len(findings),
        "findings": findings[:MAX_FINDINGS],
        "scanner_results": {
            result.scanner: {
                "status": result.status,
                "findings": len(result.findings),
                "error": result.error,
            }
            for result in results
        },
    }


def scanner_catalog() -> list[dict[str, Any]]:
    scanners: list[Scanner] = [BanditScanner(), SemgrepScanner(), GitleaksScanner(), PipAuditScanner(), NpmAuditScanner()]
    file_types = {
        "Bandit": [".py"],
        "Semgrep": [".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".c", ".h"],
        "Gitleaks": ["text source and configuration files"],
        "pip-audit": ["requirements.txt with pinned name==version entries"],
        "npm audit": ["package.json + package-lock.json"],
    }
    return [
        {
            "name": scanner.name,
            "available": scanner.available(),
            "supported_file_types": file_types[scanner.name],
        }
        for scanner in scanners
    ]


def scan_python_project(project_path: str):
    """Backward-compatible Bandit-oriented entry point retained for existing callers."""
    return scan_project(project_path, include_dependency_audits=False)