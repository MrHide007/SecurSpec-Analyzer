import React from 'react';
import { AuditReport } from '../types/analyzer';
import { ShieldCheck, ShieldAlert, Lock, AlertTriangle, CheckCircle2, Clock, Award, Shield } from 'lucide-react';

interface MetricsOverviewProps {
  report: AuditReport;
}

export const MetricsOverview: React.FC<MetricsOverviewProps> = ({ report }) => {
  const { summary, metadata, ssl_tls } = report;

  const getGradeColor = (grade: string) => {
    switch (grade) {
      case 'A+':
      case 'A':
      case 'A-':
        return 'text-emerald-700 bg-emerald-50 border-emerald-200';
      case 'B':
      case 'B+':
        return 'text-blue-700 bg-blue-50 border-blue-200';
      case 'C':
        return 'text-amber-700 bg-amber-50 border-amber-200';
      case 'D':
      case 'F':
      default:
        return 'text-rose-700 bg-rose-50 border-rose-200';
    }
  };

  const owaspScore = summary.owasp_compliance_score ?? 50;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* Metric 1: Security Posture Grade */}
      <div className="bg-white border border-slate-200 rounded-lg p-5">
        <div className="flex items-center justify-between text-xs text-slate-500 mb-2">
          <span className="font-medium text-slate-600">Overall Grade</span>
          <span className="font-mono text-slate-400">OWASP Level</span>
        </div>
        <div className="flex items-baseline gap-3">
          <div
            className={`w-12 h-12 rounded-lg border flex items-center justify-center text-2xl font-bold font-mono ${getGradeColor(
              summary.grade
            )}`}
          >
            {summary.grade}
          </div>
          <div>
            <div className="text-sm font-semibold text-slate-900">
              {summary.grade.startsWith('A')
                ? 'Strong Protection'
                : summary.grade.startsWith('B')
                ? 'Moderate Posture'
                : summary.grade.startsWith('C')
                ? 'Needs Hardening'
                : 'High Exposure'}
            </div>
            <div className="text-xs text-slate-500 mt-0.5">
              {summary.total_findings === 0
                ? 'All core headers configured'
                : `${summary.total_findings} security opportunities`}
            </div>
          </div>
        </div>
      </div>

      {/* Metric 2: OWASP Compliance Score */}
      <div className="bg-white border border-slate-200 rounded-lg p-5">
        <div className="flex items-center justify-between text-xs text-slate-500 mb-2">
          <span className="font-medium text-slate-600">OWASP Compliance</span>
          <span className="font-mono tabular-nums text-slate-400">
            {owaspScore}/100 Pts
          </span>
        </div>
        <div className="flex items-baseline gap-2">
          <div className="text-2xl font-bold text-slate-900 font-mono tabular-nums">
            {owaspScore}
          </div>
          <span className="text-xs text-slate-400 font-mono">/ 100</span>
        </div>
        {/* Compliance Progress Bar */}
        <div className="mt-2.5 space-y-1">
          <div className="w-full bg-slate-100 rounded-full h-1.5 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                owaspScore >= 80 ? 'bg-emerald-500' : owaspScore >= 60 ? 'bg-blue-500' : 'bg-rose-500'
              }`}
              style={{ width: `${Math.min(100, Math.max(5, owaspScore))}%` }}
            />
          </div>
          <div className="flex justify-between text-[11px] text-slate-400 font-mono">
            <span>{summary.headers_present_count}/8 Headers</span>
            <span>{summary.headers_missing_count} Missing</span>
          </div>
        </div>
      </div>

      {/* Metric 3: SSL / TLS Certificate Status */}
      <div className="bg-white border border-slate-200 rounded-lg p-5">
        <div className="flex items-center justify-between text-xs text-slate-500 mb-2">
          <span className="font-medium text-slate-600">SSL / TLS Protocol</span>
          <span className="font-mono text-slate-400">
            {ssl_tls?.tls_version || (metadata.target.is_https ? 'HTTPS' : 'HTTP')}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <div className="text-2xl font-bold text-slate-900 font-mono">
            {ssl_tls?.is_valid ? 'Valid Cert' : metadata.target.is_https ? 'Invalid' : 'Plaintext'}
          </div>
        </div>
        <div className="mt-2 text-xs text-slate-500 flex items-center gap-1.5">
          {ssl_tls?.days_remaining !== undefined && ssl_tls?.days_remaining !== null ? (
            <>
              <Clock className="w-3.5 h-3.5 text-slate-400" />
              <span className="font-mono tabular-nums">
                {ssl_tls.days_remaining} days remaining
              </span>
            </>
          ) : (
            <span>{ssl_tls?.reason || 'Verified via standard trust store'}</span>
          )}
        </div>
      </div>

      {/* Metric 4: Severity Breakdown */}
      <div className="bg-white border border-slate-200 rounded-lg p-5">
        <div className="flex items-center justify-between text-xs text-slate-500 mb-2">
          <span className="font-medium text-slate-600">Findings by Severity</span>
          <span className="font-mono tabular-nums text-slate-400">
            Total {summary.total_findings}
          </span>
        </div>
        <div className="grid grid-cols-3 gap-2 pt-1">
          <div className="border border-rose-100 bg-rose-50/50 rounded p-2 text-center">
            <div className="text-xs text-rose-700 font-medium">High</div>
            <div className="text-lg font-bold text-rose-900 font-mono tabular-nums">
              {summary.high_severity}
            </div>
          </div>
          <div className="border border-amber-100 bg-amber-50/50 rounded p-2 text-center">
            <div className="text-xs text-amber-700 font-medium">Med</div>
            <div className="text-lg font-bold text-amber-900 font-mono tabular-nums">
              {summary.medium_severity}
            </div>
          </div>
          <div className="border border-slate-200 bg-slate-50 rounded p-2 text-center">
            <div className="text-xs text-slate-600 font-medium">Low</div>
            <div className="text-lg font-bold text-slate-800 font-mono tabular-nums">
              {summary.low_severity}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
