import Link from "next/link";
import { ArrowLeft, ArrowRight, Clock3, FileCode2, ShieldAlert } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { FindingsTable } from "@/components/findings-table";
import { DemoDataFlag, PageHeading, SeverityBadge } from "@/components/ui";
import { demoSeverityCounts } from "@/lib/demo-data";

export const instant = false;

export default async function ScanResultsPage({ params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params;
  const total = Object.values(demoSeverityCounts).reduce((sum, count) => sum + count, 0);
  return <AppShell>
    <Link className="back-link" href="/dashboard"><ArrowLeft size={14} /> Back to overview</Link>
    <PageHeading eyebrow="SCAN RESULTS / SAMPLE" title="atlas-api" description={`Illustrative findings for scan ${scanId}. This is not a real scan result.`} action={<DemoDataFlag />} />
    <div className="scan-meta-row"><span><FileCode2 size={14} /> Python project archive</span><span><Clock3 size={14} /> Example scan · Today, 10:42 AM</span><span className="scan-id">ID: {scanId}</span></div>
    <section className="scan-summary-grid">
      <article className="scan-summary-total"><span className="summary-icon"><ShieldAlert size={17} /></span><div><small>Sample findings</small><b>{total}</b><span>Example data only</span></div><div className="summary-severities">{(["critical", "high", "medium", "low"] as const).map((severity) => <div key={severity}><SeverityBadge severity={severity} /><b>{demoSeverityCounts[severity]}</b></div>)}</div></article>
      <article className="scan-summary-note"><span className="notice-mark">i</span><div><b>Sample result set</b><p>Finding names, rules, locations, and counts on this page are illustrative UI data. They are not produced by Semgrep, Bandit, Gitleaks, or pip-audit.</p><Link href="/upload">Start a real scan when available <ArrowRight size={13} /></Link></div></article>
    </section>
    <section className="workspace-panel findings-panel">
      <div className="panel-heading"><div><h2>Findings</h2><p>Filter by severity, scanner, or finding type</p></div><DemoDataFlag /></div>
      <FindingsTable />
    </section>
  </AppShell>;
}