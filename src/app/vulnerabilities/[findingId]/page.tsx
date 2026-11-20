import Link from "next/link";
import { ArrowLeft, Copy, FileCode2, Lightbulb, ShieldAlert, ShieldCheck } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { CodeComparison } from "@/components/code-comparison";
import { DemoDataFlag, PageHeading, SeverityBadge, StatusPill } from "@/components/ui";
import { demoFindings } from "@/lib/demo-data";

export const instant = false;

export default async function VulnerabilityPage({ params }: { params: Promise<{ findingId: string }> }) {
  const { findingId } = await params;
  const finding = demoFindings.find((item) => item.id === findingId) ?? demoFindings[0];
  const before = finding.id === "ARG-1021"
    ? "query = f\"SELECT * FROM users WHERE name = '{name}'\"\ncursor.execute(query)"
    : finding.id === "ARG-1042"
      ? "with open(upload_path, 'rb') as archive:\n    record = pickle.load(archive)"
      : "# Example source context is redacted in this preview\nvalue = read_from_request()\nprocess(value)";
  const after = finding.id === "ARG-1021"
    ? "query = \"SELECT * FROM users WHERE name = %s\"\ncursor.execute(query, (name,))"
    : finding.id === "ARG-1042"
      ? "# Use a constrained, non-executable data format\nrecord = json.loads(validated_payload)"
      : "# Read sensitive values from a managed secret store\nvalue = settings.get_required_value()\nprocess(value)";
  return <AppShell>
    <Link className="back-link" href="/scans/demo-scan"><ArrowLeft size={14} /> Back to sample findings</Link>
    <PageHeading eyebrow={`FINDING DETAILS / ${finding.id}`} title={finding.title} description={finding.summary} action={<DemoDataFlag />} />
    <div className="detail-meta"><SeverityBadge severity={finding.severity} /><span><FileCode2 size={14} />{finding.file}:{finding.line}</span><span>{finding.scanner} / {finding.ruleId}</span><StatusPill tone="warning">Unverified sample</StatusPill></div>
    <div className="detail-layout">
      <div className="detail-main">
        <section className="workspace-panel detail-section"><div className="detail-section-title"><span className="detail-title-icon danger"><ShieldAlert size={16} /></span><div><h2>Why this matters</h2><small>Illustrative explanation</small></div></div><p>{finding.summary} If exploitable in a real project, this pattern could undermine expected security controls. Confirm the surrounding code and trust boundary before changing it.</p><div className="impact-note"><b>Potential impact</b><span>Depends on reachable code paths, input control, and deployment context. The scanner finding alone is not proof of exploitability.</span></div></section>
        <section className="workspace-panel detail-section"><div className="detail-section-title"><span className="detail-title-icon"><FileCode2 size={16} /></span><div><h2>Affected location</h2><small>{finding.file} · line {finding.line}</small></div><button className="icon-button detail-copy" title="Copy file path" aria-label="Copy file path"><Copy size={14} /></button></div><div className="code-block"><div className="code-block-head"><span>{finding.file}</span><span>Sample context only</span></div><pre><code>{before}</code></pre></div><div className="sample-code-notice">Code shown is illustrative and does not come from an uploaded project.</div></section>
        <section className="workspace-panel detail-section"><div className="detail-section-title"><span className="detail-title-icon guidance"><Lightbulb size={16} /></span><div><h2>Before and safer pattern</h2><small>Illustrative remediation guidance, not AI-generated</small></div></div><CodeComparison before={before} after={after} /><p className="guidance-copy">Adapt this example to the project&apos;s libraries and input validation strategy. Review changes before applying them.</p></section>
      </div>
      <aside className="detail-aside">
        <section className="workspace-panel detail-aside-panel"><div className="aside-heading"><ShieldCheck size={16} /><h3>Verification</h3></div><StatusPill tone="warning">Not verified</StatusPill><p>No follow-up scan exists for this sample finding. ARGUS does not mark issues resolved based on a recommendation or manual assertion.</p><Link className="aside-cta" href="/remediation">View verification workflow <span aria-hidden="true">&rarr;</span></Link></section>
        <section className="workspace-panel detail-aside-panel"><div className="aside-heading"><FileCode2 size={16} /><h3>Finding metadata</h3></div><dl className="metadata-list"><div><dt>Finding ID</dt><dd>{finding.id}</dd></div><div><dt>Scanner</dt><dd>{finding.scanner}</dd></div><div><dt>Rule</dt><dd>{finding.ruleId}</dd></div><div><dt>Category</dt><dd>{finding.category}</dd></div><div><dt>Project</dt><dd>{finding.project}</dd></div></dl></section>
      </aside>
    </div>
  </AppShell>;
}