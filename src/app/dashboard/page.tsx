import Link from "next/link";
import {
  ArrowRight,
  ArrowUpRight,
  FolderOpen,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { DemoDataFlag, MetricCard, PageHeading, StatusPill } from "@/components/ui";
import { demoProjects, demoScanActivity, demoSeverityCounts } from "@/lib/demo-data";

const severities = ["critical", "high", "medium", "low"] as const;

export default function DashboardPage() {
  const total = Object.values(demoSeverityCounts).reduce((sum, count) => sum + count, 0);

  return (
    <AppShell>
      <PageHeading
        eyebrow="SECURITY OVERVIEW"
        title="Good morning, developer."
        description="A clearer view of your project's security posture starts here."
        action={<DemoDataFlag />}
      />
      <div className="demo-notice"><span className="notice-mark">i</span><p><b>Preview workspace.</b> All projects, counts, and activity below are sample data. Connect the FastAPI backend to show real scans.</p><Link href="/upload">Upload project <ArrowRight size={14} /></Link></div>

      <section className="metric-grid" aria-label="Sample security metrics">
        <MetricCard label="Projects scanned" value="03" note="Sample projects" icon={<FolderOpen size={16} />} tone="blue" />
        <MetricCard label="Findings" value={total} note="Across sample scans" icon={<ShieldAlert size={16} />} tone="red" />
        <MetricCard label="Critical findings" value={demoSeverityCounts.critical} note="Sample data only" icon={<TriangleAlert size={16} />} tone="amber" />
        <MetricCard label="Verified fixes" value="--" note="No verification scans yet" icon={<ShieldCheck size={16} />} tone="cyan" />
      </section>

      <section className="dashboard-grid">
        <article className="workspace-panel distribution-panel">
          <div className="panel-heading"><div><h2>Finding distribution</h2><p>Sample severity breakdown</p></div><DemoDataFlag /></div>
          <div className="distribution-body">
            <div className="distribution-chart" aria-label={`Sample findings: ${total} total`}>
              <div className="chart-center"><b>{total}</b><span>findings</span></div>
              <span className="donut-segment donut-critical" /><span className="donut-segment donut-high" /><span className="donut-segment donut-medium" /><span className="donut-segment donut-low" />
            </div>
            <div className="distribution-legend">
              {severities.map((severity) => <div key={severity}><span className={`legend-dot legend-${severity}`} /><span className="legend-name">{severity}</span><b>{demoSeverityCounts[severity]}</b><span className="legend-percent">{Math.round(demoSeverityCounts[severity] / total * 100)}%</span></div>)}
            </div>
          </div>
          <Link className="panel-link" href="/scans/demo-scan">Review sample findings <ArrowRight size={14} /></Link>
        </article>

        <article className="workspace-panel activity-panel">
          <div className="panel-heading"><div><h2>Recent scan activity</h2><p>Illustrative history, not live scans</p></div><DemoDataFlag /></div>
          <div className="activity-list">
            {demoScanActivity.map((scan) => <div className="activity-row" key={scan.project}>
              <span className="activity-icon"><ShieldCheck size={15} /></span>
              <div className="activity-copy"><b>{scan.project}</b><span>{scan.action} · {scan.date}</span></div>
              <div className="activity-result"><b>{scan.findings}</b><span>findings</span></div>
            </div>)}
          </div>
          <Link className="panel-link" href="/reports">View scan history <ArrowRight size={14} /></Link>
        </article>
      </section>

      <section className="workspace-panel projects-panel" id="projects">
        <div className="panel-heading"><div><h2>Recent projects</h2><p>Example project inventory for layout preview</p></div><Link className="panel-action" href="/upload">Add project <ArrowUpRight size={14} /></Link></div>
        <div className="table-scroll"><table className="workspace-table">
          <thead><tr><th>Project</th><th>Language</th><th>Findings</th><th>Latest sample scan</th><th>Review state</th><th><span className="sr-only">Open project</span></th></tr></thead>
          <tbody>{demoProjects.map((project) => <tr key={project.name}>
            <td><span className="project-cell"><span className="project-avatar"><FolderOpen size={15} /></span><b>{project.name}</b></span></td>
            <td><span className="language-tag">{project.language}</span></td>
            <td><b className="finding-count">{project.findings}</b><span className="critical-mini"> {project.critical > 0 ? `${project.critical} critical` : "no critical"}</span></td>
            <td className="table-muted">{project.updated}</td>
            <td><StatusPill tone={project.status === "Reviewed" ? "success" : "warning"}>{project.status}</StatusPill></td>
            <td><Link className="row-link" href="/scans/demo-scan" aria-label={`View sample findings for ${project.name}`}><ArrowUpRight size={15} /></Link></td>
          </tr>)}</tbody>
        </table></div>
        <div className="table-footnote"><span><i className="sample-dot" /> Sample data</span><span>Project activity shown for interface preview only.</span></div>
      </section>
      <div className="dashboard-foot"><span>ARGUS PREVIEW</span><span>Scanner and database integrations are not connected.</span></div>
    </AppShell>
  );
}