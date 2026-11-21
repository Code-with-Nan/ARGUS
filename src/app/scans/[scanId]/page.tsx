import { Suspense } from "react";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { LoadingState, PageHeading } from "@/components/ui";
import { ScanResultsClient } from "@/components/scan-results-client";

export const instant = false;

export default async function ScanResultsPage({ params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params;
  return (
    <AppShell>
      <Link className="back-link" href="/dashboard"><ArrowLeft size={14} /> Back to overview</Link>
      <PageHeading
        eyebrow="SCAN RESULTS"
        title="Security scan"
        description={`Persisted results for scan ${scanId}.`}
      />
      <Suspense fallback={<LoadingState label="Loading scan results…" />}>
        <ScanResultsClient scanId={scanId} />
      </Suspense>
    </AppShell>
  );
}
