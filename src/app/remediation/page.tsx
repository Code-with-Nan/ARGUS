import Link from "next/link";
import { ArrowRight, Check, CircleDot, ClipboardCheck, RotateCw, ShieldAlert, ShieldCheck } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { DemoDataFlag, PageHeading, SeverityBadge, StatusPill } from "@/components/ui";
import { demoFindings } from "@/lib/demo-data";

export default function RemediationPage() {
  const finding = demoFindings[0];
  return <AppShell>
    <PageHeading eyebrow="VERIFIED REMEDIATION" title="A fix is a hypothesis." description="A follow-up scan is the evidence. Keep review, approval, and verification distinct." action={<DemoDataFlag />} />
    <div className="verification-banner"><span className="verification-banner-icon"><ShieldCheck size={19} /></span><div><b>Verification is unavailable in this preview.</b><p>No remediation is marked resolved without a real follow-up scan and comparison.</p></div><StatusPill tone="warning">Awaiting backend</StatusPill></div>
    <section className="verification-workflow">
      <div className="verification-steps">
        <article className="verification-step step-complete"><span className="verification-step-icon"><Check size={15} /></span><div><small>STEP 01 · ORIGINAL FINDING</small><b>Detected in baseline scan</b><span>Sample finding only</span></div></article>
        <article className="verification-step"><span className="verification-step-icon"><ClipboardCheck size={15} /></span><div><small>STEP 02 · REVIEW</small><b>Developer review and approval</b><span>Not started</span></div></article>
        <article className="verification-step"><span className="verification-step-icon"><RotateCw size={15} /></span><div><small>STEP 03 · FOLLOW-UP SCAN</small><b>Rescan updated project</b><span>Not available</span></div></article>
        <article className="verification-step"><span className="verification-step-icon"><CircleDot size={15} /></span><div><small>STEP 04 · COMPARISON</small><b>Confirm outcome and regressions</b><span>Unverified</span></div></article>
      </div>
      <div className="verification-detail">
        <div className="verification-card-head"><div><small>ORIGINAL VULNERABILITY</small><h2>{finding.title}</h2><span>{finding.file}:{finding.line}</span></div><SeverityBadge severity={finding.severity} /></div>
        <p className="verification-description">{finding.summary}</p>
        <div className="verification-guidance"><div className="guidance-icon"><ShieldAlert size={16} /></div><div><small>ILLUSTRATIVE REMEDIATION GUIDANCE</small><p>Use a constrained, non-executable data format for untrusted serialized input. Review compatibility and validation requirements for the actual project.</p><span>This guidance is sample copy, not an AI-generated recommendation.</span></div></div>
        <div className="approval-actions"><button className="button button-disabled" disabled>Developer approval unavailable</button><span>Review actions require a connected backend.</span></div>
      </div>
    </section>
    <section className="workspace-panel verification-results">
      <div className="panel-heading"><div><h2>Verification results</h2><p>Outcome is unknown until an updated scan completes</p></div><StatusPill tone="warning">Unverified</StatusPill></div>
      <div className="result-checks"><div><span className="result-pending"><CircleDot size={15} /></span><span><b>Original finding resolved</b><small>No follow-up scan to compare</small></span><strong>Unknown</strong></div><div><span className="result-pending"><CircleDot size={15} /></span><span><b>New findings introduced</b><small>Regression check not run</small></span><strong>Unknown</strong></div><div><span className="result-pending"><CircleDot size={15} /></span><span><b>Verification evidence</b><small>Baseline and follow-up scan IDs unavailable</small></span><strong>Not available</strong></div></div>
      <Link className="panel-link" href="/scans/demo-scan">Review sample findings <ArrowRight size={14} /></Link>
    </section>
  </AppShell>;
}