// Browser scan mode, no backend and no login: loading and scanning run in a Web Worker (worker.js), so a large
// repository never freezes the page; where workers are unavailable the same job runs on the main thread. Folder,
// ZIP and file scans keep the code in the browser (the only request is the optional OSV.dev lookup of package
// names and versions); GitHub scans fetch the repository from GitHub. This module stays small: the engine and its
// rules load with the worker, or on demand for the fallback.

const cancelled = () => Object.assign(new Error("Scan cancelled."), { name: "AbortError" });
const CRASHED = "The scan stopped unexpectedly in the browser (it may have run out of memory). "
  + "Try a smaller folder or a trimmed ZIP.";

/** file-selector's path properties and webkitRelativePath do not survive a structured clone, so read them here. */
const withPath = (file) => ({ file, path: file.relativePath || file.path || file.webkitRelativePath || file.name });

/**
 * Scan in the browser. kind: "github" (input: repo URL; token optional, kept in memory and sent to api.github.com
 * only), "zip" (input: File or ArrayBuffer) or "files" (input: File[] or FileList). onProgress(stage, pct 0-100).
 * Returns {promise, cancel}: promise resolves to an analysis shaped like the server's (mode "browser") and rejects
 * with a user-facing message; cancel() stops the scan and rejects with an AbortError.
 */
export function runLocalScan({ kind, input, name, token, osv = true }, onProgress = () => {}) {
  const job = { kind, input: kind === "files" ? Array.from(input || [], withPath) : input, name, token, osv };
  const controller = new AbortController();
  let worker = null;
  let settled = false;
  let settle;
  const promise = new Promise((resolve, reject) => {
    settle = { resolve, reject };
  });
  const finish = (outcome, value) => {
    if (settled) return;
    settled = true;
    worker?.terminate();
    worker = null;
    settle[outcome](value);
  };
  const progress = (stage, pct) => {
    if (!settled) onProgress(stage, pct);
  };

  const inline = async () => {
    if (settled) return;
    worker?.terminate();
    worker = null;
    let mod;
    try {
      mod = await import("./worker");
    } catch {
      finish("reject", new Error("Couldn't load the scanner. Reload the page and try again."));
      return;
    }
    try {
      finish("resolve", await mod.runJob(job, progress, { signal: controller.signal }));
    } catch (err) {
      finish("reject", err?.name === "AbortError" ? cancelled() : new Error(mod.userMessage(err)));
    }
  };

  try {
    if (typeof Worker !== "undefined") worker = new Worker(new URL("./worker.js", import.meta.url));
  } catch {
    worker = null; // e.g. a CSP without worker-src
  }
  if (!worker) inline();
  else {
    let started = false;
    worker.onmessage = ({ data }) => {
      started = true;
      if (data?.type === "progress") progress(data.stage, data.pct);
      else if (data?.type === "done") finish("resolve", data.analysis);
      else if (data?.type === "error") finish("reject", new Error(data.message));
    };
    worker.onerror = (event) => {
      event.preventDefault?.();
      if (settled) return;
      if (started) finish("reject", new Error(CRASHED));
      else inline(); // the worker script never ran
    };
    worker.onmessageerror = () => finish("reject", new Error("Couldn't read the scan result. Try again."));
    try {
      worker.postMessage({ type: "start", job });
    } catch {
      inline(); // the job could not be cloned
    }
  }

  return {
    promise,
    cancel() {
      controller.abort();
      finish("reject", cancelled());
    },
  };
}
