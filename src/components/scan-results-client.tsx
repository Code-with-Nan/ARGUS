"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiRequest, API_BASE_URL, ApiRequestError } from "@/lib/api";

type Finding = {
  id: number;
  title: string;
  severity: string;
  confidence: string;
  file: string;
  line: number;
  scanner: string;
  rule_id: string | null;
  description: string | null;
  explanation: string | null;
  explanation_source: string | null;
};

type Scan = {
  scan_id: string;
  project_name: string;
  status: string;
  scanner: string;
  total_findings: number;
  created_at: string;
  scanner_results: Record<string, { status: string; findings?: number; error?: string | null }>;
  findings: Finding[];
  remediations: Array<{ id: string; status: string; rational?: string }>;
};

export function ScanResultsClient({ scanId }: { scanId: string }) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    apiRequest<Scan>(`/api/v1/scans/${scanId}`)
      .then((result) => {
        if (active) setScan(result);
      })
      .catch((caught) => {
        if (!active) return;
        if (caught instanceof ApiRequestError && caught.status === 401) {
          window.location.replace("/login");
          return;
        }
        setError("Could not load this scan. Check that the backend is running and you are signed in.");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [scanId]);

  if (loading) return <section className="workspace-panel"><p>Loading scan results…</p></section>;
  if (error) return <section className="workspace-panel"><p role="alert">{error}</p><Link className="text-link" href="/dashboard">Back to projects</Link></section>;
  if (!scan) return null;

  return (
    <div className="detail-layout">
      <div className="detail-main">
        <section className="workspace-panel">
          <div className="panel-heading">
            <div><h2>{scan.project_name}</h2><p>Scan {scan.scan_id} · {new Date(scan.created_at).toLocaleString()}</p></div>
            <span className={`status-pill status-${scan.status === "completed" ? "success" : "warning"}`}><i />{scan.status}</span>
          </div>
          <p>Scanners completed: {scan.scanner || "None"} · Findings: {scan.total_findings}</p>
          <div className="scanner-list">
            {Object.entries(scan.scanner_results).map(([name, result]) => (
              <div key={name}><b>{name}</b><span>{result.status}</span><span>{result.findings ?? 0} findings</span></div>
            ))}
          </div>
          <p><a className="text-link" href={`${API_BASE_URL}/api/v1/scans/${scan.scan_id}/report.pdf`}>Download PDF report</a></p>
        </section>

        <section className="workspace-panel findings-panel">
          <div className="panel-heading"><div><h2>Findings</h2><p>Real results persisted from the uploaded archive</p></div></div>
          {scan.findings.length === 0 ? <p>No findings were recorded for this scan.</p> : (
            <div className="table-scroll">
              <table className="workspace-table findings-table">
                <thead><tr><th>Finding</th><th>Severity</th><th>Scanner / rule</th><th>Location</th></tr></thead>
                <tbody>
                  {scan.findings.map((finding) => (
                    <tr key={finding.id}>
                      <td>
                        <b>{finding.title}</b>
                        {finding.explanation ? <small className="rule-id">{finding.explanation}</small> : <small className="rule-id">No explanation generated yet.</small>}
                      </td>
                      <td><span className={`severity-badge severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span></td>
                      <td><span className="scanner-name">{finding.scanner}</span><small className="rule-id">{finding.rule_id ?? "—"}</small></td>
                      <td><span className="file-location">{finding.file}</span><small className="rule-id">Line {finding.line}</small></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
      <aside className="detail-aside">
        <section className="workspace-panel detail-aside-panel">
          <h3>Remediation</h3>
          {scan.remediations.length === 0 ? <p>No remediation has been proposed for this scan.</p> : scan.remediations.map((item) => (
            <p key={item.id}>Suggestion {item.id}: <b>{item.status}</b></p>
          ))}
        </section>
      </aside>
    </div>
  );
}
