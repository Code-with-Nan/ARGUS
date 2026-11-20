import { AppShell } from "@/components/app-shell";
import { FileUpload } from "@/components/file-upload";
import { PageHeading } from "@/components/ui";

export default function UploadPage() {
  return <AppShell><PageHeading eyebrow="PROJECT INTAKE" title="Start a security review." description="Choose a Python project archive to prepare a scan." /><FileUpload /></AppShell>;
}