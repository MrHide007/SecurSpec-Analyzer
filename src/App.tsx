/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { AuditReport } from './types/analyzer';
import { INITIAL_SAMPLE_REPORT } from './data/sampleReport';
import { TopNav } from './components/TopNav';
import { AuditSearchBar } from './components/AuditSearchBar';
import { MetricsOverview } from './components/MetricsOverview';
import { HeadersTab } from './components/HeadersTab';
import { SslTab } from './components/SslTab';
import { RemediationTab } from './components/RemediationTab';
import { PythonCliTab } from './components/PythonCliTab';
import { JsonReportTab } from './components/JsonReportTab';
import { exportAuditPdf } from './utils/pdfExport';
import { AlertCircle, Shield, FileText, CheckCircle2 } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [report, setReport] = useState<AuditReport>(INITIAL_SAMPLE_REPORT);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [scanStage, setScanStage] = useState<string>('Initializing...');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [lastRequestedUrl, setLastRequestedUrl] = useState<string>('https://example.com');
  const [lastRequestedNoSsl, setLastRequestedNoSsl] = useState<boolean>(false);

  const handleAnalyze = async (url: string, noSsl: boolean) => {
    setIsLoading(true);
    setErrorMessage(null);
    setLastRequestedUrl(url);
    setLastRequestedNoSsl(noSsl);

    // Dynamic progression states for live UX feedback
    setScanStage('Initializing connection & DNS lookup...');
    const t1 = setTimeout(() => {
      setScanStage('Connecting TLS & verifying X.509 certificate trust store...');
    }, 450);

    const t2 = setTimeout(() => {
      setScanStage('Requesting HTTP headers & auditing RFC/OWASP policies...');
    }, 1100);

    const t3 = setTimeout(() => {
      setScanStage('Calculating OWASP compliance score and hardening directives...');
    }, 1800);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url, noSsl, timeout: 8 }),
      });

      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Failed to complete configuration audit.');
      }

      setReport(data.report);
    } catch (err: any) {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      setErrorMessage(
        err.message || 'Target host is unreachable or connection timed out. Please check the URL syntax and retry.'
      );
    } finally {
      setIsLoading(false);
      setScanStage('Complete');
    }
  };

  const handleRetry = () => {
    if (lastRequestedUrl) {
      handleAnalyze(lastRequestedUrl, lastRequestedNoSsl);
    }
  };

  const handleDownloadScript = () => {
    window.location.href = '/api/python-script?download=true';
  };

  const handleExportPdf = () => {
    exportAuditPdf(report);
  };

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col text-slate-900">
      {/* Top Header */}
      <TopNav
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onDownloadScript={handleDownloadScript}
        onExportPdf={handleExportPdf}
      />

      {/* Target URL Search / Audit Bar */}
      <AuditSearchBar
        onAnalyze={handleAnalyze}
        isLoading={isLoading}
        scanStage={scanStage}
        currentUrl={report.metadata.target.url}
        errorMessage={errorMessage}
        onRetry={handleRetry}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 w-full space-y-6">
        {/* Target Meta Kicker */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-slate-200 text-xs text-slate-500 gap-2">
          <div className="flex flex-wrap items-center gap-2 font-mono">
            <span className="font-semibold text-slate-800">Target:</span>
            <span className="text-slate-900 font-bold bg-white px-2 py-0.5 border border-slate-200 rounded">
              {report.metadata.target.url}
            </span>
            <span className="text-slate-400">·</span>
            <span>Port {report.metadata.target.port}</span>
            <span className="text-slate-400">·</span>
            <span className={report.metadata.target.is_https ? 'text-emerald-700 font-medium' : 'text-rose-600 font-medium'}>
              {report.metadata.target.is_https ? 'HTTPS (TLS)' : 'HTTP (Plaintext)'}
            </span>
            {report.summary.owasp_compliance_score !== undefined && (
              <>
                <span className="text-slate-400">·</span>
                <span className="text-slate-700 bg-slate-100 px-1.5 py-0.5 rounded border border-slate-200">
                  OWASP Score: <strong className="font-bold text-slate-900">{report.summary.owasp_compliance_score}/100</strong>
                </span>
              </>
            )}
          </div>

          <div className="flex items-center gap-3 font-mono text-slate-400 text-right">
            <span>Audited: {new Date(report.metadata.timestamp).toLocaleTimeString()} UTC</span>
            <button
              onClick={handleExportPdf}
              className="text-slate-700 hover:text-slate-900 underline font-sans flex items-center gap-1"
            >
              <FileText className="w-3.5 h-3.5 text-slate-600" />
              <span>Export PDF Report</span>
            </button>
          </div>
        </div>

        {/* Top Metrics Cards */}
        <MetricsOverview report={report} />

        {/* Tab View Container */}
        <div className="pt-2">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              <HeadersTab headers={report.headers} />
            </div>
          )}

          {activeTab === 'headers' && (
            <div className="space-y-6">
              <HeadersTab headers={report.headers} />
            </div>
          )}

          {activeTab === 'ssl' && (
            <div className="space-y-6">
              <SslTab ssl={report.ssl_tls} targetUrl={report.metadata.target.url} />
            </div>
          )}

          {activeTab === 'remediation' && (
            <div className="space-y-6">
              <RemediationTab
                guide={report.remediation_guide}
                missingHeaders={report.headers.missing_headers}
                targetHostname={report.metadata.target.hostname}
              />
            </div>
          )}

          {activeTab === 'cli' && (
            <div className="space-y-6">
              <PythonCliTab
                onDownloadScript={handleDownloadScript}
                targetUrl={report.metadata.target.url}
              />
            </div>
          )}

          {activeTab === 'json' && (
            <div className="space-y-6">
              <JsonReportTab report={report} />
            </div>
          )}
        </div>
      </main>

      {/* Quiet Footer */}
      <footer className="bg-white border-t border-slate-200 mt-12 py-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-600" />
            <span className="font-semibold text-slate-700">SecurSpec</span>
            <span>— Defensive Web Configuration & Security Header Analyzer</span>
          </div>

          <div className="flex items-center gap-4 text-slate-400 font-mono">
            <span>Python 3 Standard Library Engine</span>
            <span>·</span>
            <span>Zero External Dependencies</span>
            <span>·</span>
            <button
              onClick={handleExportPdf}
              className="hover:text-slate-700 transition-colors underline"
            >
              Export PDF
            </button>
            <span>·</span>
            <button
              onClick={handleDownloadScript}
              className="hover:text-slate-700 transition-colors underline"
            >
              Get CLI Script
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
