"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { apiRequest, ApiRequestError } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      await apiRequest("/api/v1/auth/login", {
        method: "POST",
        body: { email, password },
      });
      router.replace("/dashboard");
    } catch (caught) {
      setError(caught instanceof ApiRequestError && caught.status === 401 ? "Invalid email or password." : "Unable to sign in. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="workspace-content" style={{ maxWidth: 480, margin: "80px auto" }}>
      <h1>Sign in to ARGUS</h1>
      <form onSubmit={submit}>
        <label>Email<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required /></label>
        <label>Password<input type="password" minLength={12} value={password} onChange={(event) => setPassword(event.target.value)} required /></label>
        {error ? <p role="alert">{error}</p> : null}
        <button type="submit" disabled={loading}>{loading ? "Signing in…" : "Sign in"}</button>
      </form>
      <p><Link href="/register">Create an account</Link></p>
    </main>
  );
}
