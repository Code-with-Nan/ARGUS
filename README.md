# ARGUS

### See What AI Code Hides.

![Status](https://img.shields.io/badge/status-planning-orange)
![Hackathon](https://img.shields.io/badge/The%20Big%20Hack%202.0-R1%20%E2%80%93%20Vibe--coded%20and%20Vulnerable-blue)

ARGUS is a security inspection platform for Python projects built with AI assistance. It is being developed for **The Big Hack 2.0** at Acharya College, Bengaluru, under the problem statement **R1 – Vibe-coded and Vulnerable**.

> **Status:** planning and early development. No scanning features are implemented yet.

---

## Why ARGUS

AI coding tools help us build faster than ever. But code that runs is not always code that is safe. A leaked API key, an unsafe `eval()` call, or an outdated dependency can sit quietly in a project that looks finished.

Most of us check whether the app works. Few of us check whether it is secure. ARGUS is our attempt to make that first security review faster and easier to understand.

---

## The Problem

AI-generated code often looks clean, which creates a false sense of confidence. The same issues keep appearing:

- **Secrets in source code** — API keys, passwords, and tokens pasted directly into files.
- **Unsafe patterns** — `eval()` on user input, `shell=True`, debug mode left on, weak hashing.
- **Vulnerable dependencies** — packages in `requirements.txt` with known CVEs.
- **Unclear reports** — findings written for security experts, not beginners.
- **No easy verification** — after a fix, it is hard to tell what was actually resolved.

Manual review catches some of this, but it is the first thing skipped when a deadline is close.

---

## Our Solution

ARGUS lets a developer upload a Python project, runs established open-source security scanners, and explains the results in plain language with practical fixes.

To be clear about scope: ARGUS will not detect every possible vulnerability, and it is not a replacement for a professional security audit. It is an early warning system for common, high-impact issues.

---

## How It Works

```
Upload  →  Scan  →  Detect  →  Explain  →  Fix  →  Verify
```

1. **Upload** — the user submits a Python project as a ZIP file, which is validated before processing.
2. **Scan** — the archive is unpacked in an isolated directory; nothing from the project is executed.
3. **Detect** — static analysis, secret detection, and a dependency audit run against the files.
4. **Explain** — findings are normalized into one format and described in beginner-friendly language.
5. **Fix** — each issue comes with a practical recommendation or safer code pattern.
6. **Verify** — the updated project can be rescanned and compared with the previous results.

---

## Closing

AI is helping us write more code than ever, but our habits for reviewing it have not kept up. ARGUS is the tool we want to use before shipping a project, and we think security feedback should be understandable to the person who has to fix it.

---

*Built for The Big Hack 2.0 · R1 – Vibe-coded and Vulnerable · Acharya College, Bengaluru*
