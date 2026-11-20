import type { ReactNode } from "react";
import { ArrowDownRight, CircleAlert, LoaderCircle } from "lucide-react";
import type { Severity } from "@/lib/demo-data";

export function DemoDataFlag({ className = "" }: { className?: string }) {
  return <span className={`demo-flag ${className}`.trim()}>Demo data</span>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity-badge severity-${severity}`}>{severity}</span>;
}

export function StatusPill({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "success" | "warning" | "info" }) {
  return <span className={`status-pill status-${tone}`}><i />{children}</span>;
}

export function PageHeading({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div><div className="page-eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>
      {action ? <div className="page-heading-action">{action}</div> : null}
    </div>
  );
}

export function MetricCard({
  label,
  value,
  note,
  icon,
  tone = "blue",
}: {
  label: string;
  value: string | number;
  note: string;
  icon: ReactNode;
  tone?: "blue" | "red" | "amber" | "cyan";
}) {
  return (
    <article className={`metric-card metric-${tone}`}>
      <div className="metric-top"><span>{label}</span><span className="metric-icon">{icon}</span></div>
      <strong>{value}</strong>
      <div className="metric-note">{note}</div>
    </article>
  );
}

export function EmptyState({ title, description, action }: { title: string; description: string; action?: ReactNode }) {
  return (
    <div className="empty-state">
      <span className="empty-icon"><ArrowDownRight size={17} /></span>
      <h3>{title}</h3><p>{description}</p>
      {action ? <div className="empty-action">{action}</div> : null}
    </div>
  );
}

export function LoadingState({ label = "Loading" }: { label?: string }) {
  return <div className="state-line"><LoaderCircle size={16} className="spin" />{label}</div>;
}

export function ErrorState({ title = "Something went wrong", description }: { title?: string; description: string }) {
  return <div className="error-state"><CircleAlert size={18} /><div><b>{title}</b><p>{description}</p></div></div>;
}