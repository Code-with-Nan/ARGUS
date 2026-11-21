"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { AppShell } from "@/components/app-shell";
import { apiRequest, ApiRequestError } from "@/lib/api";

type Project = { id: string; name: string; description: string | null; scan_count: number; finding_count: number; updated_at: string };

export default function DashboardPage() {
  const router = useRouter();
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        await apiRequest("/api/v1/auth/me");
        const result = await apiRequest<{ items: Project[] }>("/api/v1/projects");
        if (active) setProjects(result.items);
      } catch (caught) {
        if (caught instanceof ApiRequestError && caught.status === 401) router.replace("/login");
        else if (active) setError("Could not load your projects.");
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => { active = false; };
  }, [router]);

  async function logout() {
    try {
      await apiRequest("/api/v1/auth/logout", { method: "POST" });
    } finally {
      router.replace("/login");
    }
  }

  return (
    <AppShell>
      <section className="workspace-panel">
        <div className="panel-heading">
          <div>
            <h1>Projects</h1>
            <p>Your real projects and persisted scan activity</p>
          </div>
          <Link className="panel-action" href="/projects/new">
            Create project
          </Link>
        </div>
        {loading ? <p>Loading projects…</p> : null}
        {error ? <p role="alert">{error}</p> : null}
        {!loading && !error && projects.length === 0 ? (
          <p>No projects yet. Create a project before uploading a scan.</p>
        ) : null}
        {projects.length ? (
          <div className="table-scroll">
            <table className="workspace-table">
              <thead>
                <tr>
                  <th>Project</th>
                  <th>Scans</th>
                  <th>Findings</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {projects.map((project) => (
                  <tr key={project.id}>
                    <td>
                      <Link href={`/projects/${project.id}`}>
                        <b>{project.name}</b>
                      </Link>
                    </td>
                    <td>{project.scan_count}</td>
                    <td>{project.finding_count}</td>
                    <td>{new Date(project.updated_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
        <button type="button" onClick={logout}>
          Log out
        </button>
      </section>
    </AppShell>
  );
}