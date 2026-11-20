import os
import re
import stat
import tempfile
from pathlib import Path, PurePosixPath


_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
MAX_PATCH_SIZE = 100_000


def suggest_fix(finding: dict[str, object]) -> tuple[str, str]:
    package = finding.get("package")
    fixed_version = finding.get("fixed_version")
    if package and fixed_version:
        return (
            f"Upgrade {package} to version {fixed_version} or a later supported release, then rerun the dependency audit.",
            "The scanner reports a fixed version for the affected dependency. Confirm compatibility and update the project manifest and lockfile together.",
        )
    title = str(finding.get("title") or "the reported issue")
    return (
        f"Review the reported {title} and implement a minimal change that removes the risky behavior while preserving the intended functionality.",
        "No safe automatic code patch can be inferred from scanner output alone. A developer must review and supply any patch before approval.",
    )


def _validated_path(root: Path, header_path: str) -> Path:
    if header_path.startswith(("/", "\\")) or "\\" in header_path:
        raise ValueError("Patch paths must be relative POSIX paths")
    relative = PurePosixPath(header_path)
    if not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
        raise ValueError("Unsafe patch path")
    untrusted_path = root / Path(*relative.parts)
    current = untrusted_path
    while current != root.parent:
        if current.is_symlink():
            raise ValueError("Patch paths cannot traverse symbolic links")
        if current == root:
            break
        current = current.parent
    destination = untrusted_path.resolve()
    if not destination.is_relative_to(root):
        raise ValueError("Patch path escapes the working copy")
    if not destination.is_file() or destination.is_symlink():
        raise ValueError("Patch may only modify an existing regular file")
    return destination


def _apply_file_hunks(original: str, hunk_lines: list[str]) -> str:
    source = original.splitlines(keepends=True)
    output: list[str] = []
    source_index = 0
    index = 0
    saw_hunk = False

    while index < len(hunk_lines):
        header = hunk_lines[index].rstrip("\r\n")
        match = _HUNK_HEADER.match(header)
        if not match:
            raise ValueError("Invalid unified diff hunk header")
        saw_hunk = True
        old_start = int(match.group(1))
        expected_old = int(match.group(2) or "1")
        expected_new = int(match.group(4) or "1")
        hunk_start = max(old_start - 1, 0)
        if hunk_start < source_index or hunk_start > len(source):
            raise ValueError("Patch hunks are out of order or outside the file")
        output.extend(source[source_index:hunk_start])
        source_index = hunk_start
        consumed_old = 0
        produced_new = 0
        index += 1

        while index < len(hunk_lines) and not hunk_lines[index].startswith("@@ "):
            line = hunk_lines[index]
            if line.startswith("\\"):
                raise ValueError("No-newline diff markers are not supported")
            if not line or line[0] not in " +-":
                raise ValueError("Invalid unified diff line")
            value = line[1:]
            if line[0] in " -":
                if source_index >= len(source) or source[source_index] != value:
                    raise ValueError("Patch context does not match the current file")
                source_index += 1
                consumed_old += 1
            if line[0] in " +":
                output.append(value)
                produced_new += 1
            index += 1

        if consumed_old != expected_old or produced_new != expected_new:
            raise ValueError("Patch hunk line counts are invalid")

    if not saw_hunk:
        raise ValueError("Patch contains no file changes")
    output.extend(source[source_index:])
    return "".join(output)


def _parse_patch(root: Path, patch: str) -> list[tuple[Path, str]]:
    if not patch or len(patch.encode("utf-8")) > MAX_PATCH_SIZE:
        raise ValueError("Patch is empty or exceeds the size limit")
    lines = patch.splitlines(keepends=True)
    results: list[tuple[Path, str]] = []
    index = 0
    seen: set[Path] = set()

    while index < len(lines):
        if not lines[index].startswith("--- a/"):
            raise ValueError("Patch must contain standard a/ and b/ file headers")
        old_path = lines[index][6:].rstrip("\r\n")
        index += 1
        if index >= len(lines) or not lines[index].startswith("+++ b/"):
            raise ValueError("Patch file headers do not match")
        new_path = lines[index][6:].rstrip("\r\n")
        index += 1
        if old_path != new_path:
            raise ValueError("File creation, deletion, and rename patches are not allowed")
        destination = _validated_path(root, old_path)
        if destination in seen:
            raise ValueError("Patch contains duplicate file sections")
        seen.add(destination)

        hunk_lines = []
        while index < len(lines) and not lines[index].startswith("--- "):
            hunk_lines.append(lines[index])
            index += 1
        original = destination.read_text(encoding="utf-8")
        results.append((destination, _apply_file_hunks(original, hunk_lines)))

    if not results:
        raise ValueError("Patch contains no file changes")
    return results


def validate_unified_diff(workspace: str | Path, patch: str) -> list[str]:
    root = Path(workspace).resolve()
    if not root.is_dir():
        raise ValueError("Working copy is unavailable")
    return [destination.relative_to(root).as_posix() for destination, _ in _parse_patch(root, patch)]


def apply_unified_diff(workspace: str | Path, patch: str) -> list[str]:
    root = Path(workspace).resolve()
    if not root.is_dir():
        raise ValueError("Working copy is unavailable")
    updates = _parse_patch(root, patch)
    staged: list[tuple[Path, str]] = []
    try:
        for destination, content in updates:
            file_mode = stat.S_IMODE(destination.stat().st_mode)
            descriptor, temp_name = tempfile.mkstemp(prefix=".argus-fix-", dir=destination.parent)
            temp_path = Path(temp_name)
            staged.append((temp_path, str(destination)))
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temp_path, file_mode)
        for temp_path, destination in staged:
            os.replace(temp_path, destination)
    except Exception:
        for temp_path, _ in staged:
            temp_path.unlink(missing_ok=True)
        raise
    return [destination.relative_to(root).as_posix() for destination, _ in updates]