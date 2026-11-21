"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowDownToLine, ArrowRight, FileBarChart2 } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { EmptyState, ErrorState, LoadingState, MetricCard, PageHeading, SeverityBadge, StatusPill } from "@/components/ui";
import { apiRequest, API_BASE_URL, ApiRequestError } from "@/lib/api";

type Severity = "critical" | "high" | "medium" | "low";
type Tone = "neutral" | "success" | "warning" | "info";

type ScanSummary = {
  scan_id: string;
  project_name: string;
  status: string;
  scanner: string;
  total_findings: number;
  created_at: string;
};

type ReportFinding = {
  id: number;
  title: string;
  severity: string;
  confidence: string;
  file: string;
  line: number;
  scanner: string;
  rule_id: string | null;
  explanation: string | null;
};

type VerificationRecord = {
  id: number;
  status: string;
  target_finding_present: boolean | null;
  message: string;
  followup_scan_id: string | null;
  created_at: string;
};

type ReportMetrics = {
  fix_verification_rate: number | null;
  verified_resolutions: number;
  completed_verifications: number;
  regression_count: number;
  average_remediation_seconds: number | null;
  remediation_time_samples: number;
  accuracy_status: string;
};

type SecurityReport = {
  scan_id: string;
  project_name: string;
  scan_timestamp: string;
  scan_status: string;
  total_findings: number;
  severity_breakdown: Record<string, number>;
  findings: ReportFinding[];
  verification_results: VerificationRecord[];
  metrics: ReportMetrics;
  limitations: string[];
};

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function formatRate(value: number | null | undefined) {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  return `${(value * 100).toFixed(1)}%`;
}

function formatDuration(seconds: number | null | undefined) {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return "—";
  return seconds < 60 ? `${seconds.toFixed(1)}s` : `${(seconds / 60).toFixed(1)}m`;
}

function severityTone(value: string): Severity {
  const severity = value.toLowerCase();
  if (severity.includes("critical")) return "critical";
  if (severity.includes("high")) return "high";
  if (severity.includes("medium") || severity.includes("moderate")) return "medium";
  return "low";
}

function statusTone(status: string): Tone {
  if (status === "completed" || status === "VERIFIED_FIXED") return "success";
  if (status === "failed" || status === "REGRESSION_DETECTED" || status === "STILL_PRESENT") return "warning";
  return "info";
}

export default function ReportsPage() {
  const router = useRouter();
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [reportLoading, setReportLoading] = useState(false);
  const [error, setError] = useState("");
  const [reportError, setReportError] = useState("");

  useEffect(() => {
    let active = true;
    async function loadHistory() {
      try {
        const result = await apiRequest<{ items: ScanSummary[] }>("/api/v1/scans?page=1&page_size=20");
        if (!active) return;
        setScans(result.items);
        if (result.items.length) setSelectedScanId(result.items[0].scan_id);
      } catch (caught) {
        if (caught instanceof ApiRequestError && caught.status === 401) {
          router.replace("/login");
          return;
        }
        if (active) setError("Could not load real scan history.");
      } finally {
        if (active) setLoading(false);
      }
    }
    loadHistory();
    return () => { active = false; };
  }, [router]);

  useEffect(() => {
    if (!selectedScanId) return;
    let active = true;
    setReportLoading(true);
    setReportError("");
    setReport(null);
    apiRequest<SecurityReport>(`/api/v1/scans/${selectedScanId}/report.json`)
      .then((result) => {
        if (active) setReport(result);
      })
      .catch((caught) => {
        if (!active) return;
        if (caught instanceof ApiRequestError && caught.status === 401) {
          router.replace("/login");
          return;
        }
        setReportError("Could not load the JSON report for this scan.");
      })
      .finally(() => {
        if (active) setReportLoading(false);
      });
    return () => { active = false; };
  }, [router, selectedScanId]);

  const metrics = report?.metrics;
  const pdfUrl = selectedScanId
    ? `${API_BASE_URL}/api/v1/scans/${selectedScanId}/report.pdf`
    : "";

  return (
    <AppShell>
      <PageHeading
        eyebrow="REPORTS & HISTORY"
        title="Security history."
        description="Persisted scan reports generated from real backend findings and verification records."
      />

      {loading ? <LoadingState label="Loading real scan reports…" /> : null}
      {error ? <ErrorState title="Report history unavailable" description={error} /> : null}

      {!loading && !error && scans.length === 0 ? (
        <>
          <div className="report-callout">
            <span className="report-callout-icon"><FileBarChart2 size={17} /></span>
            <div>
              <b>No security reports have been generated.</b>
              <p>Upload a project ZIP and run a scan to create a real report. No sample findings are shown.</p>
            </div>
            <Link className="button" href="/upload"><ArrowRight size={15} /> Upload a project</Link>
          </div>
          <div className="report-empty">
            <EmptyState
              title="No exportable report"
              description="Reports are generated only after the backend persists a real scan."
              action={<Link className="text-link" href="/dashboard">Back to overview <ArrowRight size={14} /></Link>}
            />
          </div>
        </>
      ) : null}

      {scans.length ? (
        <>
          <div className="report-callout">
            <span className="report-callout-icon"><FileBarChart2 size={17} /></span>
            <div>
              <b>{report?.project_name || scans.find((item) => item.scan_id === selectedScanId)?.project_name}</b>
              <p>
                Scan {selectedScanId} · {report ? formatDate(report.scan_timestamp) : "loading report data"}
              </p>
            </div>
            <a className="button" href={pdfUrl} target="_blank" rel="noreferrer">
              <ArrowDownToLine size={15} /> Download PDF
            </a>
          </div>

          <div className="metric-grid">
            <MetricCard
              label="Findings"
              value={report?.total_findings ?? "—"}
              note="Persisted scanner results"
              icon={<FileBarChart2 size={14} />}
              tone="red"
            />
            <MetricCard
              label="Fix verification rate"
              value={formatRate(metrics?.fix_verification_rate)}
              note={`${metrics?.verified_resolutions ?? 0} of ${metrics?.completed_verifications ?? 0} completed remediations resolved`}
              icon={<ArrowRight size={14} />}
              tone="cyan"
            />
            <MetricCard
              label="Regressions"
              value={metrics?.regression_count ?? "—"}
              note="Actual REGRESSION_DETECTED outcomes"
              icon={<FileBarChart2 size={14} />}
              tone="amber"
            />
            <MetricCard
              label="Avg remediation time"
              value={formatDuration(metrics?.average_remediation_seconds)}
              note={`${metrics?.remediation_time_samples ?? 0} timed verification samples`}
              icon={<FileBarChart2 size={14} />}
              tone="blue"
            />
          </div>

          <section className="workspace-panel report-history">
            <div className="panel-heading">
              <div><h2>Scan history</h2><p>Real scans owned by the signed-in user</p></div>
            </div>
            <div className="table-scroll">
              <table className="workspace-table">
                <thead>
                  <tr><th>Project</th><th>Activity</th><th>Findings</th><th>Run date</th><th>State</th><th>Report</th></tr>
                </thead>
                <tbody>
                  {scans.map((scan) => (
                    <tr key={scan.scan_id}>
                      <td><b>{scan.project_name}</b></td>
                      <td>{scan.scanner || "No scanners completed"}</td>
                      <td><b className="finding-count">{scan.total_findings}</b></td>
                      <td className="table-muted">{formatDate(scan.created_at)}</td>
                      <td><StatusPill tone={statusTone(scan.status)}>{scan.status}</StatusPill></td>
                      <td>
                        <button
                          className="text-link"
                          type="button"
                          onClick={() => setSelectedScanId(scan.scan_id)}
                          disabled={scan.scan_id === selectedScanId}
                        >
                          {scan.scan_id === selectedScanId ? "Selected" : "View report"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="table-footnote"><span>{scans.length} persisted scans</span><span>Latest scan selected by default</span></div>
          </section>

          {reportLoading ? <LoadingState label="Loading real report data…" /> : null}
          {reportError ? <ErrorState title="Report unavailable" description={reportError} /> : null}

          {report ? (
            <>
              <section className="workspace-panel report-history">
                <div className="panel-heading">
                  <div><h2>Scan findings</h2><p>Real findings stored for this scan</p></div>
                  <Link className="text-link" href={`/scans/${report.scan_id}`}>Open scan <ArrowRight size={13} /></Link>
                </div>
                {report.findings.length === 0 ? (
                  <p>No findings were recorded for this scan.</p>
                ) : (
                  <div className="table-scroll">
                    <table className="workspace-table">
                      <thead>
                        <tr><th>Finding</th><th>Severity</th><th>Scanner</th><th>Location</th></tr>
                      </thead>
                      <tbody>
                        {report.findings.map((finding) => (
                          <tr key={finding.id}>
                            <td>
                              <b>{finding.title}</b>
                              {finding.explanation ? <small className="rule-id">{finding.explanation}</small> : null}
                            </td>
                            <td><SeverityBadge severity={severityTone(finding.severity)} /></td>
                            <td>{finding.scanner}<small className="rule-id">{finding.rule_id ?? "—"}</small></td>
                            <td>{finding.file}<small className="rule-id">Line {finding.line}</small></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              <section className="workspace-panel report-history">
                <div className="panel-heading">
                  <div><h2>Verification records</h2><p>Persisted fix-verification outcomes</p></div>
                </div>
                {report.verification_results.length === 0 ? (
                  <p>No remediation verification has been recorded for this scan.</p>
                ) : (
                  <div className="table-scroll">
                    <table className="workspace-table">
                      <thead>
                        <tr><th>Status</th><th>Outcome</th><th>Follow-up scan</th><th>Recorded</th></tr>
                      </thead>
                      <tbody>
                        {report.verification_results.map((result) => (
                          <tr key={result.id}>
                            <td><StatusPill tone={statusTone(result.status)}>{result.status}</StatusPill></td>
                            <td>{result.message}</td>
                            <td>
                              {result.followup_scan_id ? (
                                <Link className="text-link" href={`/scans/${result.followup_scan_id}`}>{result.followup_scan_id}</Link>
                              ) : (
                                <span className="table-muted">—</span>
                              )}
                            </td>
                            <td className="table-muted">{formatDate(result.created_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              <div className="report-callout">
                <span className="report-callout-icon"><FileBarChart2 size={17} /></span>
                <div><b>Accuracy status</b><p>{metrics?.accuracy_status}</p></div>
              </div>
            </>
          ) : null}
        </>
      ) : null}
    </AppShell>
  );
}
