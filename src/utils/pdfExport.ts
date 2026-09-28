import { AuditReport } from '../types/analyzer';

export function exportAuditPdf(report: AuditReport) {
  const { metadata, summary, headers, ssl_tls, findings } = report;
  const targetHost = metadata.target.hostname;
  const dateStr = new Date(metadata.timestamp).toUTCString();

  const printWindow = window.open('', '_blank');
  if (!printWindow) {
    alert('Please allow popups to generate and save the PDF report.');
    return;
  }

  const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SecurSpec Security Audit Report - ${targetHost}</title>
  <style>
    @page {
      size: A4;
      margin: 18mm 16mm;
    }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: #0f172a;
      line-height: 1.45;
      font-size: 11pt;
      margin: 0;
      padding: 0;
    }
    .header {
      border-bottom: 2px solid #0f172a;
      padding-bottom: 12px;
      margin-bottom: 16px;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
    }
    .title {
      font-size: 20pt;
      font-weight: 800;
      color: #0f172a;
      margin: 0;
      letter-spacing: -0.5px;
    }
    .subtitle {
      font-size: 9.5pt;
      color: #64748b;
      margin-top: 4px;
    }
    .meta-box {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      padding: 12px 14px;
      margin-bottom: 18px;
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      font-size: 9pt;
    }
    .meta-box div span {
      display: block;
      color: #64748b;
      font-size: 8pt;
      text-transform: uppercase;
      font-weight: 600;
      margin-bottom: 2px;
    }
    .meta-box div strong {
      font-size: 10pt;
      color: #0f172a;
      word-break: break-all;
    }
    .score-badge {
      display: inline-block;
      font-size: 22pt;
      font-weight: 800;
      font-family: monospace;
      padding: 4px 14px;
      border-radius: 6px;
      border: 1px solid #cbd5e1;
      background: #f1f5f9;
    }
    .grade-A { color: #047857; background: #ecfdf5; border-color: #a7f3d0; }
    .grade-B { color: #1d4ed8; background: #eff6ff; border-color: #bfdbfe; }
    .grade-C { color: #b45309; background: #fffbeb; border-color: #fde68a; }
    .grade-D, .grade-F { color: #b91c1c; background: #fef2f2; border-color: #fecaca; }
    h2 {
      font-size: 12pt;
      border-bottom: 1px solid #e2e8f0;
      padding-bottom: 6px;
      margin-top: 22px;
      margin-bottom: 10px;
      color: #0f172a;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 16px;
      font-size: 8.5pt;
    }
    th, td {
      border: 1px solid #e2e8f0;
      padding: 6px 8px;
      text-align: left;
      vertical-align: top;
    }
    th {
      background: #f8fafc;
      font-weight: 600;
      color: #475569;
    }
    .badge {
      display: inline-block;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 7.5pt;
      font-weight: 700;
      text-transform: uppercase;
      font-family: monospace;
    }
    .badge-High { background: #fee2e2; color: #991b1b; }
    .badge-Medium { background: #fef3c7; color: #92400e; }
    .badge-Low { background: #f1f5f9; color: #475569; }
    .mono { font-family: monospace; font-size: 8.5pt; }
    .footer {
      margin-top: 30px;
      border-top: 1px solid #e2e8f0;
      padding-top: 8px;
      font-size: 8pt;
      color: #94a3b8;
      display: flex;
      justify-content: space-between;
    }
    .rec-box {
      background: #f8fafc;
      border-left: 3px solid #0f172a;
      padding: 6px 10px;
      margin-top: 4px;
      font-family: monospace;
      font-size: 8pt;
      word-break: break-all;
    }
    @media print {
      body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .no-print { display: none; }
    }
  </style>
</head>
<body>
  <div class="no-print" style="background: #0f172a; color: white; padding: 10px 16px; margin-bottom: 16px; border-radius: 6px; display: flex; justify-content: space-between; align-items: center;">
    <span style="font-size: 10pt;">Ready to print or save as PDF. Click the button to launch standard system print dialog:</span>
    <button onclick="window.print()" style="background: #10b981; color: white; border: none; padding: 6px 16px; font-weight: bold; border-radius: 4px; cursor: pointer; font-size: 10pt;">Print / Save as PDF</button>
  </div>

  <div class="header">
    <div>
      <h1 class="title">SecurSpec Security Audit Report</h1>
      <div class="subtitle">Defensive HTTP Security Headers & TLS Certificate Verification</div>
    </div>
    <div style="text-align: right;">
      <span class="score-badge grade-${summary.grade.replace(/[^A-Za-z]/g, '')}">
        ${summary.grade}
      </span>
      <div style="font-size: 8pt; color: #64748b; margin-top: 4px;">
        OWASP Score: <strong>${summary.owasp_compliance_score ?? 'N/A'}/100</strong>
      </div>
    </div>
  </div>

  <div class="meta-box">
    <div>
      <span>Target Domain</span>
      <strong>${targetHost}</strong>
    </div>
    <div>
      <span>Protocol & Port</span>
      <strong>${metadata.target.is_https ? 'HTTPS (TLS)' : 'HTTP (Plaintext)'} : ${metadata.target.port}</strong>
    </div>
    <div>
      <span>Audit Timestamp</span>
      <strong>${dateStr}</strong>
    </div>
    <div>
      <span>Total Findings</span>
      <strong>${summary.total_findings} (High: ${summary.high_severity}, Med: ${summary.medium_severity}, Low: ${summary.low_severity})</strong>
    </div>
  </div>

  <h2>1. SSL / TLS Server Certificate Verification</h2>
  <table>
    <tr>
      <th style="width: 25%;">Property</th>
      <th>Audit Verification Value</th>
    </tr>
    <tr>
      <td>TLS Handshake Status</td>
      <td><strong>${ssl_tls?.is_valid ? 'Valid & Trusted' : 'Invalid or Unverified'}</strong></td>
    </tr>
    <tr>
      <td>Negotiated Protocol</td>
      <td class="mono">${ssl_tls?.tls_version || 'N/A'}</td>
    </tr>
    <tr>
      <td>Cipher Suite</td>
      <td class="mono">${ssl_tls?.cipher?.name || 'N/A'} (${ssl_tls?.cipher?.bits || 0} bits)</td>
    </tr>
    <tr>
      <td>Certificate Authority (Issuer)</td>
      <td>${ssl_tls?.issuer?.organizationName || ssl_tls?.issuer?.commonName || 'N/A'}</td>
    </tr>
    <tr>
      <td>Expiration Countdown</td>
      <td>${ssl_tls?.days_remaining !== undefined ? `${ssl_tls.days_remaining} days remaining (Expires: ${ssl_tls.valid_until ? new Date(ssl_tls.valid_until).toLocaleDateString() : 'N/A'})` : 'N/A'}</td>
    </tr>
  </table>

  <h2>2. Missing Security Headers Analysis (${headers.missing_headers.length})</h2>
  <table>
    <thead>
      <tr>
        <th style="width: 18%;">Severity</th>
        <th style="width: 28%;">Header Name</th>
        <th style="width: 24%;">Category</th>
        <th>Remediation Directive</th>
      </tr>
    </thead>
    <tbody>
      ${
        headers.missing_headers.length === 0
          ? '<tr><td colspan="4" style="text-align: center; color: #059669;">All 8 core security headers are enforced!</td></tr>'
          : headers.missing_headers
              .map(
                (m) => `
        <tr>
          <td><span class="badge badge-${m.severity}">${m.severity}</span></td>
          <td><strong>${m.header}</strong></td>
          <td>${m.category}</td>
          <td>
            <div style="font-size: 8pt; color: #475569;">${m.description}</div>
            <div class="rec-box">${m.header}: ${m.recommendation}</div>
          </td>
        </tr>
      `
              )
              .join('')
      }
    </tbody>
  </table>

  <h2>3. Enforced Security Headers (${headers.present_headers.length})</h2>
  <table>
    <thead>
      <tr>
        <th style="width: 28%;">Header</th>
        <th style="width: 20%;">Category</th>
        <th>Configured Value</th>
      </tr>
    </thead>
    <tbody>
      ${
        headers.present_headers.length === 0
          ? '<tr><td colspan="3" style="text-align: center; color: #dc2626;">No core defensive security headers detected.</td></tr>'
          : headers.present_headers
              .map(
                (p) => `
        <tr>
          <td><strong>${p.header}</strong></td>
          <td>${p.category}</td>
          <td class="mono" style="word-break: break-all;">${p.value}</td>
        </tr>
      `
              )
              .join('')
      }
    </tbody>
  </table>

  <div class="footer">
    <div>Generated by SecurSpec Defensive Web Configuration & Security Header Analyzer v1.1.0</div>
    <div>Confidential Audit Report · Standard RFC & OWASP Compliance</div>
  </div>

  <script>
    window.onload = function() {
      setTimeout(function() {
        window.print();
      }, 400);
    };
  </script>
</body>
</html>
  `;

  printWindow.document.open();
  printWindow.document.write(htmlContent);
  printWindow.document.close();
}
