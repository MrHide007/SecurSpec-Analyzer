import React, { useState } from 'react';
import { HeadersReport } from '../types/analyzer';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  FileCode,
  Layers,
} from 'lucide-react';

interface HeadersTabProps {
  headers: HeadersReport;
}

export const HeadersTab: React.FC<HeadersTabProps> = ({ headers }) => {
  const [filter, setFilter] = useState<'all' | 'missing' | 'present' | 'raw'>('all');
  const [copiedHeader, setCopiedHeader] = useState<string | null>(null);
  const [expandedMissing, setExpandedMissing] = useState<Record<string, boolean>>({});

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHeader(id);
    setTimeout(() => setCopiedHeader(null), 2000);
  };

  const toggleExpand = (headerName: string) => {
    setExpandedMissing((prev) => ({
      ...prev,
      [headerName]: !prev[headerName],
    }));
  };

  const getSeverityBadge = (severity: 'High' | 'Medium' | 'Low') => {
    switch (severity) {
      case 'High':
        return 'text-rose-700 bg-rose-50 border-rose-200';
      case 'Medium':
        return 'text-amber-700 bg-amber-50 border-amber-200';
      case 'Low':
        return 'text-slate-700 bg-slate-100 border-slate-200';
    }
  };

  return (
    <div className="space-y-6">
      {/* Information Disclosure Banner if detected */}
      {headers.disclosure_headers.length > 0 && (
        <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-700 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h4 className="text-xs font-semibold text-amber-900">
              Information Disclosure Headers Detected
            </h4>
            <p className="text-xs text-amber-800">
              The web server returns headers revealing server software or technology stack
              versions. An attacker can use this information for targeted vulnerability mapping.
            </p>
            <div className="flex flex-wrap gap-2 pt-1 font-mono text-xs text-amber-900">
              {headers.disclosure_headers.map((d) => (
                <span key={d.header} className="bg-amber-100/70 border border-amber-300 px-2 py-0.5 rounded">
                  {d.header}: {d.value}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Filter Segmented Controls */}
      <div className="flex items-center justify-between border-b border-slate-200 pb-3">
        <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg">
          <button
            onClick={() => setFilter('all')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              filter === 'all'
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            All Baseline ({headers.missing_headers.length + headers.present_headers.length})
          </button>
          <button
            onClick={() => setFilter('missing')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              filter === 'missing'
                ? 'bg-white text-rose-700 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Missing ({headers.missing_headers.length})
          </button>
          <button
            onClick={() => setFilter('present')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              filter === 'present'
                ? 'bg-white text-emerald-700 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Configured ({headers.present_headers.length})
          </button>
          <button
            onClick={() => setFilter('raw')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              filter === 'raw'
                ? 'bg-white text-slate-900 shadow-xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Raw Headers ({Object.keys(headers.raw_headers).length})
          </button>
        </div>

        <div className="text-xs text-slate-500 font-mono">
          HTTP {headers.status_code || 200} {headers.status_reason || 'OK'}
        </div>
      </div>

      {/* Section: Missing Headers */}
      {(filter === 'all' || filter === 'missing') && headers.missing_headers.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-900">
              Missing Security Headers ({headers.missing_headers.length})
            </h3>
            <span className="text-xs text-slate-500">
              Ranked by defensive priority & OWASP impact
            </span>
          </div>

          <div className="space-y-3">
            {headers.missing_headers.map((item) => {
              const isExpanded = expandedMissing[item.header];
              return (
                <div
                  key={item.header}
                  className="bg-white border border-slate-200 rounded-lg p-4 space-y-3 hover:border-slate-300 transition-colors"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-xs font-semibold px-2 py-0.5 rounded border font-mono ${getSeverityBadge(
                            item.severity
                          )}`}
                        >
                          {item.severity} Severity
                        </span>
                        <h4 className="text-sm font-bold text-slate-900 font-mono">
                          {item.header}
                        </h4>
                        <span className="text-xs text-slate-400 font-mono">
                          · {item.category}
                        </span>
                        {item.score_weight && (
                          <span className="text-xs text-amber-700 bg-amber-50 px-1.5 py-0.5 rounded border border-amber-200 font-mono">
                            -{item.score_weight} pts
                          </span>
                        )}
                        <span className="text-xs text-slate-400 font-mono">
                          · {item.rfc}
                        </span>
                      </div>
                      <p className="text-xs text-slate-600">{item.description}</p>
                    </div>

                    <button
                      onClick={() => toggleExpand(item.header)}
                      className="text-slate-400 hover:text-slate-600 p-1"
                      aria-label="Toggle details"
                    >
                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4" />
                      ) : (
                        <ChevronDown className="w-4 h-4" />
                      )}
                    </button>
                  </div>

                  {/* Recommendation and Remediation */}
                  <div className="bg-slate-50 border border-slate-200 rounded p-3 text-xs space-y-2">
                    <div className="flex items-center justify-between text-slate-600">
                      <span className="font-semibold">Recommended Header Directive:</span>
                      <button
                        onClick={() =>
                          handleCopy(
                            `${item.header}: ${item.recommendation}`,
                            item.header
                          )
                        }
                        className="flex items-center gap-1 text-slate-700 hover:text-slate-900 font-medium"
                      >
                        {copiedHeader === item.header ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-emerald-600" />
                            <span className="text-emerald-600">Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            <span>Copy Header</span>
                          </>
                        )}
                      </button>
                    </div>
                    <div className="font-mono text-slate-800 bg-white border border-slate-200 p-2 rounded break-all select-all">
                      <span className="text-slate-500">{item.header}: </span>
                      {item.recommendation}
                    </div>
                    <div className="text-slate-500 pt-1">
                      <span className="font-medium text-slate-700">Remediation: </span>
                      {item.remediation}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Section: Configured Headers */}
      {(filter === 'all' || filter === 'present') && (
        <div className="space-y-3 pt-2">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-900">
              Configured Security Headers ({headers.present_headers.length})
            </h3>
            <span className="text-xs text-slate-500">
              Detected in live HTTP response
            </span>
          </div>

          {headers.present_headers.length === 0 ? (
            <div className="bg-white border border-slate-200 rounded-lg p-8 text-center text-slate-500 text-xs">
              No core security headers detected in the response. Add recommended headers to protect against Clickjacking, XSS, and MIME-sniffing.
            </div>
          ) : (
            <div className="space-y-3">
              {headers.present_headers.map((item) => (
                <div
                  key={item.header}
                  className="bg-white border border-slate-200 rounded-lg p-4 space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-emerald-600" />
                      <span className="text-sm font-bold text-slate-900 font-mono">
                        {item.header}
                      </span>
                      <span className="text-xs text-slate-400 font-mono">
                        · {item.category}
                      </span>
                      {item.score_weight && (
                        <span className="text-xs text-emerald-700 bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200 font-mono">
                          +{item.score_weight} pts
                        </span>
                      )}
                    </div>

                    <button
                      onClick={() => handleCopy(item.value, item.header)}
                      className="text-xs text-slate-500 hover:text-slate-800 flex items-center gap-1"
                    >
                      {copiedHeader === item.header ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-600" />
                          <span className="text-emerald-600">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy Value</span>
                        </>
                      )}
                    </button>
                  </div>

                  <div className="font-mono text-xs text-slate-800 bg-slate-50 border border-slate-200 p-2 rounded break-all">
                    {item.value}
                  </div>

                  {item.notes.length > 0 && (
                    <div className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded p-2 flex items-start gap-2">
                      <Info className="w-4 h-4 shrink-0 mt-0.5" />
                      <div>
                        {item.notes.map((n, idx) => (
                          <div key={idx}>{n}</div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Section: Raw Response Headers */}
      {filter === 'raw' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-900">
              Raw HTTP Response Headers
            </h3>
            <button
              onClick={() =>
                handleCopy(JSON.stringify(headers.raw_headers, null, 2), 'raw_all')
              }
              className="text-xs text-slate-600 hover:text-slate-900 flex items-center gap-1"
            >
              {copiedHeader === 'raw_all' ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-600" />
                  <span className="text-emerald-600">Copied All</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy Headers Object</span>
                </>
              )}
            </button>
          </div>

          <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 font-sans">
                <tr>
                  <th className="py-2.5 px-4 w-1/3">Header Name</th>
                  <th className="py-2.5 px-4">Header Value</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {Object.entries(headers.raw_headers).map(([key, value]) => (
                  <tr key={key} className="hover:bg-slate-50/50">
                    <td className="py-2.5 px-4 font-semibold text-slate-900 break-all align-top">
                      {key}
                    </td>
                    <td className="py-2.5 px-4 text-slate-700 break-all align-top">
                      {String(value)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
