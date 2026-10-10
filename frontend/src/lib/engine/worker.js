// Browser scans off the main thread: load the source (sources.js), run the engine, and shape the report as the
// analysis document the server would store, so the report pages read it unchanged. client.js starts this module as
// a Web Worker, or imports runJob on the main thread where workers are unavailable.
//
// Protocol: in {type: "start", job}; out {type: "progress", stage, pct} ... then {type: "done", analysis} or
// {type: "error", message}. Cancelling is worker.terminate().
import { LIMITS, pyStrip } from "./lang";
import { SourceError, loadSource } from "./sources";
import { ENGINE_VERSION, scan } from "./index";

// Share of the progress bar the loader gets: a GitHub scan is mostly downloads, a local one mostly scanning.
const LOAD_SHARE = { github: 45, zip: 15, files: 15 };

const throwIfAborted = (signal) => {
  if (signal?.aborted) throw Object.assign(new Error("Scan cancelled."), { name: "AbortError" });
};

const randomId = () => {
  const uuid = globalThis.crypto?.randomUUID?.(); // secure contexts only
  return (uuid || `${Date.now().toString(16)}${Math.random().toString(16).slice(2)}`).replace(/-/g, "").slice(0, 12);
};

/** The message a failed job shows: loader and cancel messages as written, anything else like the server's. */
export function userMessage(err) {
  if (err?.name === "SourceError" || err?.name === "AbortError") return err.message;
  return `Scan failed: ${err?.name || "Error"}`;
}

function noFilesMessage({ filtered, too_large: tooLarge, binary }) {
  const why = [
    filtered && `${filtered} unsupported or vendored`,
    tooLarge && `${tooLarge} over ${LIMITS.maxFileBytes / 1024} KB`,
    binary && `${binary} binary`,
  ].filter(Boolean);
  return `No supported source files were found${why.length ? ` (skipped: ${why.join(", ")})` : ""}.`;
}

/** The server's analysis document for a finished scan (server.run_pipeline), plus what only a browser scan has. */
export function toAnalysis(report, source, job, { startedAt, finishedAt = new Date(), id = randomId() }) {
  const github = job.kind === "github";
  return {
    ...report,
    analysis_id: `local-${id}`,
    name: pyStrip(job.name || "") || source.name,
    source_type: github ? "github" : job.kind,
    source_url: github ? pyStrip(String(job.input)) : null,
    repo_meta: source.repo_meta || null,
    status: "completed",
    progress: { stage: "Done", pct: 100 },
    created_at: startedAt.toISOString(),
    completed_at: finishedAt.toISOString(),
    engine_version: ENGINE_VERSION,
    mode: "browser",
    issue_count: report.security_issues.length,
    grade: report.grade,
    // the server stores the report's errors and warnings under these names, and the report page reads them there
    scan_errors: report.errors,
    scan_warnings: report.warnings,
    skipped: source.skipped,
    source_notes: source.notes || [],
  };
}

/** Load and scan a job ({kind, input, name, token, osv}) and resolve to its analysis. The token only reaches the
 *  GitHub loader; it is not part of the result. */
export async function runJob(job, onProgress = () => {}, { signal, fetchImpl } = {}) {
  const startedAt = new Date();
  const http = fetchImpl || ((url, init) => globalThis.fetch(url, { ...init, signal }));
  const share = LOAD_SHARE[job.kind] ?? 15;
  const source = await loadSource(job, {
    signal,
    fetchImpl: http,
    onProgress: (stage, pct) => onProgress(stage, Math.round((pct * share) / 100)),
  });
  throwIfAborted(signal);
  if (!source.files.length) throw new SourceError(noFilesMessage(source.skipped));
  const report = await scan(source.files, {
    osv: job.osv !== false,
    fetchImpl: http,
    onProgress: (stage, pct) => {
      throwIfAborted(signal); // the main-thread fallback can only stop between stages
      onProgress(stage, Math.min(99, Math.round(share + (pct * (100 - share)) / 100)));
    },
  });
  throwIfAborted(signal);
  return toAnalysis(report, source, job, { startedAt });
}

const scope = globalThis;
if (typeof scope.WorkerGlobalScope !== "undefined" && scope instanceof scope.WorkerGlobalScope) {
  scope.onmessage = async ({ data }) => {
    if (data?.type !== "start") return;
    const post = (message) => scope.postMessage(message);
    post({ type: "progress", stage: "Starting", pct: 0 }); // tells the client the worker script loaded
    try {
      post({ type: "done", analysis: await runJob(data.job, (stage, pct) => post({ type: "progress", stage, pct })) });
    } catch (err) {
      if (err?.name !== "SourceError") console.error(err);
      post({ type: "error", message: userMessage(err) });
    }
  };
}
