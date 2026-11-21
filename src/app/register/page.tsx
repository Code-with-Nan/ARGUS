"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { apiRequest, ApiRequestError } from "@/lib/api";

export default function RegisterPage() {
  const router = useRouter();
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      await apiRequest("/api/v1/auth/register", {
        method: "POST",
        body: { display_name: displayName, email, password },
      });
      router.replace("/login");
    } catch (caught) {
      setError(caught instanceof ApiRequestError && caught.status === 409 ? "An account with that email already exists." : "Unable to create the account. Please check your details.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="workspace-content" style={{ maxWidth: 480, margin: "80px auto" }}>
      <h1>Create an ARGUS account</h1>
      <form onSubmit={submit}>
        <label>Display name<input value={displayName} onChange={(event) => setDisplayName(event.target.value)} required /></label>
        <label>Email<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required /></label>
        <label>Password<input type="password" minLength={12} value={password} onChange={(event) => setPassword(event.target.value)} required /></label>
        {error ? <p role="alert">{error}</p> : null}
        <button type="submit" disabled={loading}>{loading ? "Creating…" : "Create account"}</button>
      </form>
      <p><Link href="/login">Sign in instead</Link></p>
    </main>
  );
}
