export type Severity = "critical" | "high" | "medium" | "low";

export type DemoFinding = {
  id: string;
  title: string;
  severity: Severity;
  scanner: string;
  ruleId: string;
  category: string;
  file: string;
  line: number;
  summary: string;
  project: string;
};

export const demoFindings: DemoFinding[] = [
  {
    id: "ARG-1042",
    title: "Use of unsafe deserialization",
    severity: "critical",
    scanner: "Bandit",
    ruleId: "B301",
    category: "Insecure deserialization",
    file: "src/services/importer.py",
    line: 84,
    summary: "Untrusted input may be passed to a deserialization function.",
    project: "atlas-api",
  },
  {
    id: "ARG-1038",
    title: "Hard-coded credential pattern",
    severity: "high",
    scanner: "Gitleaks",
    ruleId: "generic-api-key",
    category: "Exposed secret",
    file: "config/settings.py",
    line: 27,
    summary: "A credential-like value appears in a tracked source file. Value is redacted.",
    project: "atlas-api",
  },
  {
    id: "ARG-1021",
    title: "SQL query built with string formatting",
    severity: "high",
    scanner: "Semgrep",
    ruleId: "python.sqlalchemy.security.sql-injection",
    category: "SQL injection",
    file: "src/repositories/users.py",
    line: 112,
    summary: "Query construction may allow untrusted input to alter SQL syntax.",
    project: "ledger-worker",
  },
  {
    id: "ARG-1012",
    title: "Dependency has a known advisory",
    severity: "medium",
    scanner: "pip-audit",
    ruleId: "PYSEC-2024-111",
    category: "Vulnerable dependency",
    file: "requirements.txt",
    line: 6,
    summary: "The declared package version is associated with a published advisory.",
    project: "atlas-api",
  },
  {
    id: "ARG-1009",
    title: "Debug mode enabled in configuration",
    severity: "low",
    scanner: "Bandit",
    ruleId: "B201",
    category: "Unsafe configuration",
    file: "src/app.py",
    line: 19,
    summary: "Debug configuration can expose diagnostics if enabled in production.",
    project: "notes-service",
  },
];

export const demoProjects = [
  { name: "atlas-api", language: "Python", findings: 18, critical: 2, updated: "Today, 10:42 AM", status: "Reviewed" },
  { name: "ledger-worker", language: "Python", findings: 9, critical: 0, updated: "Yesterday, 4:18 PM", status: "Needs review" },
  { name: "notes-service", language: "Python", findings: 4, critical: 0, updated: "Nov 18, 2026", status: "Reviewed" },
];

export const demoScanActivity = [
  { project: "atlas-api", action: "Sample scan completed", date: "Today, 10:42 AM", findings: 18, status: "Complete" },
  { project: "ledger-worker", action: "Sample scan completed", date: "Yesterday, 4:18 PM", findings: 9, status: "Complete" },
  { project: "notes-service", action: "Sample scan completed", date: "Nov 18, 2026", findings: 4, status: "Complete" },
];

export const demoSeverityCounts: Record<Severity, number> = {
  critical: 3,
  high: 8,
  medium: 14,
  low: 6,
};