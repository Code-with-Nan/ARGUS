"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { ArrowUpRight, Search } from "lucide-react";
import { demoFindings } from "@/lib/demo-data";
import { SeverityBadge } from "@/components/ui";

export function FindingsTable() {
  const [severity, setSeverity] = useState("all");
  const [scanner, setScanner] = useState("all");
  const [category, setCategory] = useState("all");
  const [query, setQuery] = useState("");
  const categories = [...new Set(demoFindings.map((finding) => finding.category))];
  const scanners = [...new Set(demoFindings.map((finding) => finding.scanner))];
  const filtered = useMemo(() => demoFindings.filter((finding) => {
    const matchesSeverity = severity === "all" || finding.severity === severity;
    const matchesScanner = scanner === "all" || finding.scanner === scanner;
    const matchesCategory = category === "all" || finding.category === category;
    const haystack = `${finding.title} ${finding.file} ${finding.ruleId} ${finding.project}`.toLowerCase();
    return matchesSeverity && matchesScanner && matchesCategory && haystack.includes(query.toLowerCase());
  }), [category, query, scanner, severity]);

  return <>
    <div className="finding-filters">
      <label className="filter-search"><Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search findings" aria-label="Search findings" /></label>
      <label><span className="sr-only">Filter by severity</span><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
      <label><span className="sr-only">Filter by scanner</span><select value={scanner} onChange={(event) => setScanner(event.target.value)}><option value="all">All scanners</option>{scanners.map((name) => <option key={name}>{name}</option>)}</select></label>
      <label><span className="sr-only">Filter by type</span><select value={category} onChange={(event) => setCategory(event.target.value)}><option value="all">All types</option>{categories.map((name) => <option key={name}>{name}</option>)}</select></label>
    </div>
    <div className="table-scroll"><table className="workspace-table findings-table">
      <thead><tr><th>Finding</th><th>Severity</th><th>Scanner / rule</th><th>Location</th><th>Project</th><th><span className="sr-only">Details</span></th></tr></thead>
      <tbody>{filtered.map((finding) => <tr key={finding.id}>
        <td><Link className="finding-title-link" href={`/vulnerabilities/${finding.id}`}><b>{finding.title}</b><small>{finding.id} · {finding.category}</small></Link></td>
        <td><SeverityBadge severity={finding.severity} /></td>
        <td><span className="scanner-name">{finding.scanner}</span><small className="rule-id">{finding.ruleId}</small></td>
        <td><span className="file-location">{finding.file}</span><small className="rule-id">Line {finding.line}</small></td>
        <td className="table-muted">{finding.project}</td>
        <td><Link className="row-link" href={`/vulnerabilities/${finding.id}`} aria-label={`View details for ${finding.id}`}><ArrowUpRight size={15} /></Link></td>
      </tr>)}</tbody>
    </table></div>
    {filtered.length === 0 ? <div className="filter-empty">No demo findings match these filters.</div> : <div className="table-footnote"><span>Showing {filtered.length} sample findings</span><span>Illustrative data only; no scanner is connected.</span></div>}
  </>;
}