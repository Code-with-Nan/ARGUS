import Link from "next/link";
import { ArrowDownToLine, ArrowRight, FileBarChart2, FileText } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { DemoDataFlag, EmptyState, PageHeading, SeverityBadge, StatusPill } from "@/components/ui";
import { demoProjects, demoScanActivity } from "@/lib/demo-data";

export default function ReportsPage() {
  return <AppShell>
    <PageHeading eyebrow="REPORTS & HISTORY" title="Security history." description="Review scan activity and project summaries. Export becomes available with real scan data." action={<DemoDataFlag />} />
    <div className="report-callout"><span className="report-callout-icon"><FileBarChart2 size={17} /></span><div><b>No security reports have been generated.</b><p>Entries below are sample interface data. ARGUS will not export a report until real backend scan results are available.</p></div><button className="button button-disabled" type="button" disabled><ArrowDownToLine size={15} /> Export unavailable</button></div>
    <section className="workspace-panel report-history">
      <div className="panel-heading"><div><h2>Scan history</h2><p>Example activity only</p></div><DemoDataFlag /></div>
      <div className="table-scroll"><table className="workspace-table"><thead><tr><th>Project</th><th>Activity</th><th>Sample findings</th><th>Remediation</th><th>Run date</th><th>State</th></tr></thead>
        <tbody>{demoScanActivity.map((scan, index) => <tr key={scan.project}><td><b>{scan.project}</b></td><td>{scan.action}</td><td><b className="finding-count">{scan.findings}</b></td><td><SeverityBadge severity={index === 0 ? "high" : "medium"} /></td><td className="table-muted">{scan.date}</td><td><StatusPill tone="info">Sample</StatusPill></td></tr>)}</tbody>
      </table></div>
      <div className="table-footnote"><span>{demoProjects.length} example projects</span><span>No real scan history is stored.</span></div>
    </section>
    <section className="report-summary-grid">
      {demoProjects.map((project) => <article className="workspace-panel report-project-card" key={project.name}><div className="report-project-head"><span className="report-project-icon"><FileText size={16} /></span><StatusPill tone="info">Sample</StatusPill></div><h3>{project.name}</h3><p>Illustrative project summary</p><div className="report-project-count"><b>{project.findings}</b><span>sample findings</span></div><Link href="/scans/demo-scan">View sample breakdown <ArrowRight size={13} /></Link></article>)}
    </section>
    <div className="report-empty"><EmptyState title="No exportable report" description="Reports are generated from persisted scan records after the FastAPI backend is integrated." action={<Link className="text-link" href="/dashboard">Back to overview <ArrowRight size={14} /></Link>} /></div>
  </AppShell>;
}