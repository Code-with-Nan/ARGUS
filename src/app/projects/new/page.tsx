"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { AppShell } from "@/components/app-shell";
import { apiRequest } from "@/lib/api";

export default function NewProjectPage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      const project = await apiRequest<{ id: string }>("/api/v1/projects", { method: "POST", body: { name, description: description || null } });
      router.replace(`/projects/${project.id}`);
    } catch {
      setError("Could not create the project.");
    } finally {
      setLoading(false);
    }
  }

  return <AppShell><section className="workspace-panel"><h1>Create project</h1><form onSubmit={submit}><label>Project name<input value={name} onChange={(event) => setName(event.target.value)} maxLength={255} required /></label><label>Description<textarea value={description} onChange={(event) => setDescription(event.target.value)} maxLength={4000} /></label>{error ? <p role="alert">{error}</p> : null}<button type="submit" disabled={loading}>{loading ? "Creating…" : "Create project"}</button></form></section></AppShell>;
}
