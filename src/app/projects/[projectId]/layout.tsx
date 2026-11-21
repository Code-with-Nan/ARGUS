import { Suspense } from "react";

export const instant = false;

export default function ProjectLayout({ children }: { children: React.ReactNode }) {
  return <Suspense fallback={<p>Loading project…</p>}>{children}</Suspense>;
}
