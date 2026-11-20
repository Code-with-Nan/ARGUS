"use client";

import { useRef, useState } from "react";
import Link from "next/link";
import { Archive, Check, CircleAlert, FileArchive, Info, ShieldCheck, Trash2, UploadCloud } from "lucide-react";

type SelectedArchive = { file: File; sizeLabel: string };
const MAX_FILE_BYTES = 50 * 1024 * 1024;

function formatSize(bytes: number) {
  return bytes >= 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

export function FileUpload() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [selected, setSelected] = useState<SelectedArchive | null>(null);
  const [error, setError] = useState("");
  const [isDragging, setIsDragging] = useState(false);

  function chooseFile(file?: File) {
    setError("");
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".zip")) {
      setSelected(null);
      setError("Choose a ZIP archive. Other file types are not accepted.");
      return;
    }
    if (file.size > MAX_FILE_BYTES) {
      setSelected(null);
      setError("This archive is larger than 50 MB. Choose a smaller ZIP file.");
      return;
    }
    if (file.size === 0) {
      setSelected(null);
      setError("This archive is empty. Choose a ZIP file with project files.");
      return;
    }
    setSelected({ file, sizeLabel: formatSize(file.size) });
  }

  return (
    <div className="upload-layout">
      <section className="workspace-panel upload-panel">
        <div className="upload-step-head"><span className="step-number">01</span><div><h2>Select a project archive</h2><p>ZIP files only · up to 50 MB</p></div></div>
        <input ref={inputRef} className="sr-only" type="file" accept=".zip,application/zip" onChange={(event) => chooseFile(event.target.files?.[0])} aria-hidden="true" tabIndex={-1} />
        <div
          className={`drop-zone ${isDragging ? "drop-zone-active" : ""} ${selected ? "drop-zone-selected" : ""}`}
          role="button"
          tabIndex={0}
          aria-label="Choose a ZIP archive"
          onClick={() => inputRef.current?.click()}
          onDragOver={(event) => { event.preventDefault(); setIsDragging(true); }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={(event) => { event.preventDefault(); setIsDragging(false); chooseFile(event.dataTransfer.files[0]); }}
          onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") inputRef.current?.click(); }}
        >
          <span className="drop-icon">{selected ? <FileArchive size={23} /> : <UploadCloud size={24} />}</span>
          <b>{selected ? "Archive selected" : "Drop your ZIP archive here"}</b>
          <span>{selected ? "Select another archive to replace it" : "or browse files on your device"}</span>
          <span className="browse-action">Browse files</span>
        </div>
        {error ? <div className="upload-error" role="alert"><CircleAlert size={16} />{error}</div> : null}
        {selected ? <div className="selected-file"><span className="selected-file-icon"><Archive size={17} /></span><span className="selected-file-name"><b>{selected.file.name}</b><small>{selected.sizeLabel} · ZIP archive</small></span><span className="selected-check"><Check size={15} /></span><button type="button" className="icon-button remove-file" aria-label="Remove selected file" onClick={() => { setSelected(null); if (inputRef.current) inputRef.current.value = ""; }}><Trash2 size={15} /></button></div> : null}
        <div className="upload-privacy"><ShieldCheck size={16} /><span><b>Nothing is uploaded in this preview.</b><small>Your archive stays in this browser. ARGUS does not execute uploaded code.</small></span></div>
        <div className="upload-progress-shell"><div className="upload-progress-label"><span>Upload progress</span><b>{selected ? "Not started" : "Waiting for archive"}</b></div><div className="upload-progress-track"><span /></div><small>Upload begins only after a secure backend integration is available.</small></div>
        <button className="button button-disabled scan-start-button" type="button" disabled><span>Backend not connected</span><Info size={15} /></button>
      </section>

      <aside className="upload-aside">
        <div className="upload-aside-heading"><span className="aside-icon"><Info size={16} /></span><h3>Before you scan</h3></div>
        <div className="preflight-list"><div><i>01</i><span>Upload validation and safe archive handling run on the backend.</span></div><div><i>02</i><span>Project code is inspected by scanners; it is never executed.</span></div><div><i>03</i><span>Findings appear only after a real scan completes.</span></div></div>
        <div className="upload-state"><span className="state-indicator" /><div><b>Scan service unavailable</b><p>FastAPI integration is not configured in this frontend preview.</p></div></div>
        <Link className="text-link" href="/dashboard">Return to dashboard <span aria-hidden="true">&rarr;</span></Link>
      </aside>
    </div>
  );
}