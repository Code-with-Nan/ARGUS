"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { AppShell } from "@/components/app-shell";
import { apiRequest, ApiRequestError } from "@/lib/api";

type ProjectDetail = { id: string; name: string; description: string | null; scans: Array<{ scan_id: string; status: string; total_findings: number; created_at: string }> };

function ProjectDetailContent() {
  const params = useParams<{ projectId: string }>();
  const router = useRouter();
  const [project, setProject] = useState<ProjectDetail | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    apiRequest<ProjectDetail>(`/api/v1/projects/${params.projectId}`)
      .then(setProject)
      .catch((caught) => {
        if (caught instanceof ApiRequestError && caught.status === 401) router.replace("/login");
        else setError("Could not load this project.");
      });
  }, [params.projectId, router]);

  async function removeProject() {
    if (!project || !window.confirm("Delete this project? Projects with scans cannot be deleted.")) return;
    try {
      await apiRequest(`/api/v1/projects/${project.id}`, { method: "DELETE" });
      router.replace("/dashboard");
    } catch {
      setError("Could not delete the project.");
    }
  }

  return <AppShell><section className="workspace-panel">{error ? <p role="alert">{error}</p> : null}{project ? <><h1>{project.name}</h1>{project.description ? <p>{project.description}</p> : null}<h2>Scans</h2>{project.scans.length === 0 ? <p>No scans yet.</p> : <ul>{project.scans.map((scan) => <li key={scan.scan_id}><Link href={`/scans/${scan.scan_id}`}>{scan.scan_id}</Link> — {scan.status} — {scan.total_findings} findings</li>)}</ul>}<Link className="button" href="/upload">Upload ZIP scan</Link><button type="button" onClick={removeProject}>Delete project</button></> : <p>Loading project…</p>}</section></AppShell>;
}

export default function ProjectDetailPage() {
  return (
    <Suspense fallback={<p>Loading project…</p>}>
      <ProjectDetailContent />
    </Suspense>
  );
}
