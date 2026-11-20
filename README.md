# ARGUS

### See What AI Code Hides.

![Status](https://img.shields.io/badge/status-planning-orange)
![Hackathon](https://img.shields.io/badge/The%20Big%20Hack%202.0-R1%20%E2%80%93%20Vibe--coded%20and%20Vulnerable-blue)
![Python](https://img.shields.io/badge/python-3.x-3776AB?logo=python&logoColor=white)

ARGUS is a security inspection platform for Python projects built with the help of AI. It is being developed for **The Big Hack 2.0** at Acharya College, Bengaluru, under the problem statement **R1 – Vibe-coded and Vulnerable**.

> **Project status:** planning and early development. No scanning features are implemented yet. This README describes what we intend to build.

---

## Why We're Building ARGUS

AI coding assistants have changed the way we write software. A working prototype that used to take a weekend can now be put together in an afternoon, and that is genuinely exciting.

But there is a gap between code that runs and code that is safe.

When we generate a project with an AI assistant, we usually check whether it works. We click through the UI, test a few endpoints, and move on. What we often do not check is whether an API key was pasted directly into a source file, whether a database query is built from raw user input, or whether one of the dependencies has a known vulnerability.

These problems are easy to miss, especially for students and early-career developers who may not have spent much time on security. ARGUS is our attempt to make that first security review faster and easier to understand.

---

## The Problem

AI-generated code tends to look clean. It is well formatted, reasonably commented, and often follows common patterns. That can create a false sense of confidence.

In practice, we have seen the same categories of issues come up again and again:

- **Secrets in source code.** API keys, database passwords, and tokens placed directly in Python files or configuration, sometimes with a note to "replace this later".
- **Unsafe coding patterns.** Use of `eval()` on user input, `shell=True` in subprocess calls, disabled TLS verification, debug mode left enabled, or weak password hashing.
- **Outdated or vulnerable dependencies.** A `requirements.txt` copied from an older project can quietly pull in packages with known CVEs.
- **Unclear findings.** Existing tools often report problems in language that assumes security expertise. A beginner may see a warning, not understand the impact, and close the report.
- **No easy way to verify a fix.** After making changes, it is hard to tell whether the issue was actually resolved or simply moved somewhere else.

Manual review can catch some of this, but it does not scale, and it is the first thing to be skipped when a deadline is close.

---

## Our Solution

ARGUS is intended to be a single place where a developer can upload a Python project, run a set of security checks, and get results they can actually act on.

The platform will combine established open-source security tools with an AI layer that explains findings in plain language. Instead of only saying *"B324: Use of weak MD5 hash"*, ARGUS should explain what that means in the context of the project and suggest a safer alternative.

We want to be clear about scope: ARGUS will not detect every possible vulnerability, and it is not a replacement for a professional security audit. The goal is to catch common, high-impact issues early and to help developers understand them well enough to fix them properly.

---

## Key Features (Planned)

| # | Feature | What it will do |
|---|---------|-----------------|
| 1 | **Python Project Scanning** | Accept a Python project as a ZIP file, validate it, and scan its contents. |
| 2 | **Secret Detection** | Flag accidentally exposed API keys, passwords, and authentication tokens. |
| 3 | **Vulnerability Detection** | Identify unsafe coding practices and common security weaknesses in Python code. |
| 4 | **Dependency Analysis** | Check declared libraries against known security advisories. |
| 5 | **AI-Powered Explanations** | Describe each finding in simple, beginner-friendly language. |
| 6 | **Fix Recommendations** | Suggest practical steps and safer code patterns for each issue. |
| 7 | **Rescan & Verify** | Re-scan a project to confirm whether earlier findings were resolved. |
| 8 | **Security Dashboard** | Show findings, severity levels, and scan history in one place. |

All eight features are planned. None of them are implemented at this stage.

---

## How ARGUS Is Expected to Work

```
 Upload  →  Scan  →  Detect  →  Explain  →  Fix  →  Verify
```

**1. Upload**
The user uploads a Python project as a ZIP file. The backend checks the archive before processing it, rejecting unsupported or unsafe contents.

**2. Scan**
The project is unpacked in an isolated working directory. ARGUS identifies Python source files, configuration files, and dependency manifests such as `requirements.txt`.

**3. Detect**
The scan pipeline runs several checks: static analysis for unsafe code patterns, secret detection across source and config files, and a dependency audit against known vulnerability data.

**4. Explain**
Raw tool output is normalized into a common finding format. The AI layer then produces a short explanation of what the issue is, why it matters, and how serious it is likely to be.

**5. Fix**
Each finding includes a practical recommendation. Where possible, this will include a safer version of the affected code.

**6. Verify**
The user can upload the updated project and rescan it. ARGUS compares the new results with the previous scan so resolved and remaining issues are easy to see.

---

## Planned Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Language | Python 3.x | Backend and scan pipeline |
| API | FastAPI | Upload handling, scan orchestration, results API |
| Static analysis | Bandit | Detect unsafe Python coding patterns |
| Secret detection | detect-secrets | Find credentials and tokens in files |
| Dependency audit | pip-audit | Check packages against known vulnerabilities |
| Frontend | React | Dashboard for scans, findings, and reports |
| AI layer | AI/LLM API | Plain-language explanations and fix suggestions |

Specific versions, model providers, and hosting choices will be decided during development. The table reflects our current plan, not a final commitment.

---

## Project Architecture (Planned)

The architecture below describes how we intend to structure the system. It has not been built yet and will likely change as we learn more.

```
                 React Dashboard
                        |
                        |  upload / results
                        v
                  FastAPI Backend
                        |
                        v
                 Scan Orchestrator
                        |
        +---------------+---------------+
        |               |               |
        v               v               v
     Bandit       detect-secrets     pip-audit
        |               |               |
        +---------------+---------------+
                        |
                        v
              Findings Normalizer
           (common format + severity)
                        |
                        v
              AI Explanation Layer
                        |
                        v
            Results stored & returned
                        |
                        v
                 React Dashboard
```

A few design decisions we are planning around:

- **Isolation.** Uploaded archives will be extracted into a temporary directory and never executed. Scanners read files; they do not run the project.
- **A common finding format.** Bandit, detect-secrets, and pip-audit all report differently. Normalizing their output early keeps the dashboard and AI layer simple.
- **Graceful degradation.** If the AI layer is unavailable or a response cannot be generated, the raw finding and its rule reference will still be shown.

---

## Team

| # | Name | GitHub | Role |
|---|------|--------|------|
| 1 | _Member One_ | _@username_ | _Role_ |
| 2 | _Member Two_ | _@username_ | _Role_ |
| 3 | _Member Three_ | _@username_ | _Role_ |

Team details will be added once finalised.

---

## Current Status

ARGUS is at the very beginning. The repository currently contains this README and nothing else.

| Area | Status |
|------|--------|
| Problem research and scope | Done |
| Repository and documentation | Done |
| Backend API | Not started |
| Scan pipeline | Not started |
| Secret and dependency checks | Not started |
| AI explanation layer | Not started |
| React dashboard | Not started |
| End-to-end testing | Not started |

We will update this section as work progresses. Until a feature appears here as completed, it should be treated as planned only.

---

## Future Improvements

Once the core workflow is working, we would like to explore:

- A GitHub App or pull-request check that scans changes automatically.
- Exporting reports in SARIF format for use in other security tools.
- Configurable rules, severity thresholds, and suppressions for accepted risks.
- Scan history with diffs between runs, so teams can track progress over time.
- Support for additional languages beyond Python.
- A self-hosted or offline mode for projects that cannot leave a private network.
- Authentication and shared workspaces for team use.

These are directions, not commitments. The priority is a reliable core scan before adding surface area.

---

## Closing

ARGUS started with a simple observation: AI is helping us write more code than ever, but our habits for reviewing that code have not kept up.

We are building ARGUS because we want a tool we would use ourselves before shipping a project, and because we think security feedback should be understandable to the person who has to fix it. If the project helps even a few developers catch a leaked key or an unsafe pattern before it reaches production, it will have been worth building.

---

*Built for The Big Hack 2.0 · Problem Statement R1 – Vibe-coded and Vulnerable · Acharya College, Bengaluru*
