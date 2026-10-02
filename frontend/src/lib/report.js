import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import { gradeFor } from "@/lib/theme";
import { severityCounts } from "@/lib/api";

const SEV_RGB = { critical: [208, 59, 59], high: [214, 104, 60], medium: [190, 130, 0], low: [110, 110, 110] };
const OWASP = {
  "A01:2021": "Broken Access Control", "A02:2021": "Cryptographic Failures", "A03:2021": "Injection",
  "A04:2021": "Insecure Design", "A05:2021": "Security Misconfiguration", "A06:2021": "Vulnerable Components",
  "A07:2021": "Identification & Auth Failures", "A08:2021": "Integrity Failures", "A09:2021": "Logging Failures",
  "A10:2021": "SSRF",
};

/** Builds an executive-style PDF audit report from an analysis document. */
export function exportPdf(analysis) {
  const doc = new jsPDF();
  const W = doc.internal.pageSize.getWidth();
  const grade = analysis.grade || gradeFor(analysis.overall_score);
  const counts = severityCounts(analysis); // derived from security_issues for legacy docs

  // Header band
  doc.setFillColor(12, 12, 14);
  doc.rect(0, 0, W, 38, "F");
  doc.setTextColor(0, 229, 153);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.text("CodeGuard AI · Security Audit", 14, 17);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.setTextColor(170, 170, 178);
  doc.text(`${analysis.name}   ·   ${new Date(analysis.created_at).toLocaleString()}   ·   engine v${analysis.engine_version || "2"}`, 14, 26);
  doc.text(`Scanners: ${(analysis.scanners_run || ["patterns", "secrets"]).join(", ")}`, 14, 32);

  doc.setFont("helvetica", "bold");
  doc.setFontSize(30);
  doc.setTextColor(255, 255, 255);
  doc.text(grade || "-", W - 30, 24);
  doc.setFontSize(9);
  doc.setFont("helvetica", "normal");
  doc.text(`${Math.round(analysis.overall_score || 0)}/100`, W - 31, 31);

  let y = 50;
  doc.setTextColor(20, 20, 20);
  doc.setFontSize(11);
  doc.setFont("helvetica", "bold");
  doc.text("Summary", 14, y);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.setTextColor(70, 70, 70);
  const summary = doc.splitTextToSize(analysis.ai_summary || "Static analysis completed.", W - 28);
  doc.text(summary, 14, y + 6);
  y += 8 + summary.length * 4.5;

  autoTable(doc, {
    startY: y,
    head: [["Critical", "High", "Medium", "Low", "Files", "Lines", "Maintainability"]],
    body: [[counts.critical || 0, counts.high || 0, counts.medium || 0, counts.low || 0, analysis.metrics?.total_files || 0,
            (analysis.metrics?.total_lines || 0).toLocaleString(), `${Math.round(analysis.metrics?.maintainability_index || 0)}/100`]],
    theme: "grid", styles: { fontSize: 9, halign: "center" }, headStyles: { fillColor: [24, 24, 27] },
  });
  y = doc.lastAutoTable.finalY + 8;
  if (analysis.suppressed > 0) {
    doc.setFontSize(8.5);
    doc.setTextColor(110, 110, 110);
    doc.text(`${analysis.suppressed} finding(s) suppressed in source by codeguard-ignore markers (excluded from the totals above).`, 14, y - 3);
    y += 4;
  }

  if (analysis.recommendations?.length) {
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.setTextColor(20, 20, 20);
    doc.text("Priority actions", 14, y);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(70, 70, 70);
    y += 6;
    analysis.recommendations.forEach((r, i) => {
      const lines = doc.splitTextToSize(`${i + 1}. ${r}`, W - 28);
      doc.text(lines, 14, y);
      y += lines.length * 4.5 + 1;
    });
    y += 3;
  }

  const owasp = Object.entries(analysis.owasp_counts || {});
  if (owasp.length) {
    autoTable(doc, {
      startY: y,
      head: [["OWASP Top 10 (2021)", "Findings"]],
      body: owasp.map(([k, v]) => [`${k.split(":")[0]} ${OWASP[k] || ""}`, v]),
      theme: "striped", styles: { fontSize: 8 }, headStyles: { fillColor: [24, 24, 27] }, columnStyles: { 1: { halign: "right" } },
    });
    y = doc.lastAutoTable.finalY + 8;
  }

  const issues = analysis.security_issues || [];
  if (issues.length) {
    autoTable(doc, {
      startY: y,
      head: [["Severity", "Finding", "Location", "CWE", "Engine"]],
      body: issues.map((i) => [
        (i.severity || "low").toUpperCase(), i.type, `${i.file_path}${i.line_number ? `:${i.line_number}` : ""}`, i.cwe || "-", i.scanner || "-",
      ]),
      theme: "grid", styles: { fontSize: 7.5, cellPadding: 1.8 }, headStyles: { fillColor: [24, 24, 27] },
      columnStyles: { 0: { cellWidth: 18, fontStyle: "bold" }, 3: { cellWidth: 20 }, 4: { cellWidth: 18 } },
      didParseCell: (d) => {
        if (d.section === "body" && d.column.index === 0) d.cell.styles.textColor = SEV_RGB[String(d.cell.raw).toLowerCase()] || [0, 0, 0];
      },
    });
    y = doc.lastAutoTable.finalY + 8;
  }

  const vulnerable = (analysis.dependencies || []).filter((d) => d.vulnerabilities?.length);
  if (vulnerable.length) {
    autoTable(doc, {
      startY: y,
      head: [["Package", "Version", "Ecosystem", "Advisories", "Fix"]],
      body: vulnerable.map((d) => [d.name, d.version, d.ecosystem, d.vulnerabilities.map((v) => v.aliases?.[0] || v.id).slice(0, 3).join(", "),
                                   d.vulnerabilities.find((v) => v.fixed_in)?.fixed_in || "-"]),
      theme: "grid", styles: { fontSize: 7.5 }, headStyles: { fillColor: [24, 24, 27] },
    });
  }

  if (analysis.ai_refactors?.length) {
    doc.addPage();
    let ry = 20;
    doc.setFont("helvetica", "bold");
    doc.setFontSize(14);
    doc.setTextColor(124, 58, 237);
    doc.text("AI refactors", 14, ry);
    ry += 10;
    analysis.ai_refactors.forEach((r) => {
      if (ry > 250) { doc.addPage(); ry = 20; }
      doc.setFont("helvetica", "bold");
      doc.setFontSize(10);
      doc.setTextColor(20, 20, 20);
      doc.text(r.file_path, 14, ry);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(8.5);
      doc.setTextColor(90, 90, 90);
      const exp = doc.splitTextToSize(r.explanation || "", W - 28);
      doc.text(exp, 14, ry + 5);
      ry += 8 + exp.length * 4;
      doc.setFont("courier", "normal");
      doc.setFontSize(7);
      doc.setTextColor(40, 40, 40);
      const code = doc.splitTextToSize(r.refined_code || "", W - 28).slice(0, 45);
      doc.text(code, 14, ry);
      ry += code.length * 3.2 + 10;
    });
  }

  const pages = doc.internal.getNumberOfPages();
  for (let p = 1; p <= pages; p++) {
    doc.setPage(p);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(7.5);
    doc.setTextColor(150, 150, 150);
    doc.text(`CodeGuard AI · ${analysis.analysis_id} · page ${p}/${pages}`, 14, doc.internal.pageSize.getHeight() - 8);
  }
  doc.save(`codeguard-${analysis.name.replace(/[^\w-]+/g, "-")}.pdf`);
}
