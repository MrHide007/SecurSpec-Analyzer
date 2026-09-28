import React, { useState } from 'react';
import { AuditReport } from '../types/analyzer';
import { Copy, Check, Download, FileJson, FileText } from 'lucide-react';
import { exportAuditPdf } from '../utils/pdfExport';

interface JsonReportTabProps {
  report: AuditReport;
}

export const JsonReportTab: React.FC<JsonReportTabProps> = ({ report }) => {
  const [copied, setCopied] = useState(false);
  const jsonString = JSON.stringify(report, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit_report_${report.metadata.target.hostname}_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      <div className="bg-white border border-slate-200 rounded-lg p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileJson className="w-5 h-5 text-emerald-600" />
            <h3 className="text-base font-bold text-slate-900">
              Localized Audit Report (JSON)
            </h3>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Standardized structured output for <strong className="font-mono text-slate-700">{report.metadata.target.url}</strong> including OWASP compliance score, SSL/TLS handshake, headers audit, and remediation directives.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => exportAuditPdf(report)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors"
          >
            <FileText className="w-3.5 h-3.5 text-slate-600" />
            <span>Export PDF</span>
          </button>
          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-600" />
                <span className="text-emerald-600">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5 text-slate-600" />
                <span>Copy JSON</span>
              </>
            )}
          </button>
          <button
            onClick={handleDownload}
            className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-lg transition-colors shadow-xs"
          >
            <Download className="w-3.5 h-3.5 text-emerald-400" />
            <span>Download .json</span>
          </button>
        </div>
      </div>

      {/* JSON Viewer */}
      <div className="bg-slate-900 rounded-lg overflow-hidden border border-slate-800">
        <pre className="p-4 text-xs font-mono text-emerald-300 max-h-[600px] overflow-auto selection:bg-slate-700 leading-relaxed">
          <code>{jsonString}</code>
        </pre>
      </div>
    </div>
  );
};
