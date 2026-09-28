import React from 'react';
import { ShieldCheck, Download, Terminal, FileText } from 'lucide-react';

interface TopNavProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onDownloadScript: () => void;
  onExportPdf: () => void;
}

export const TopNav: React.FC<TopNavProps> = ({
  activeTab,
  setActiveTab,
  onDownloadScript,
  onExportPdf,
}) => {
  const tabs = [
    { id: 'overview', label: 'Inspector' },
    { id: 'headers', label: 'Security Headers' },
    { id: 'ssl', label: 'SSL / TLS Cert' },
    { id: 'remediation', label: 'Remediation' },
    { id: 'cli', label: 'Python CLI' },
    { id: 'json', label: 'JSON Report' },
  ];

  return (
    <header className="bg-white border-b border-slate-200 sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Zone 1: Single text element wordmark */}
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-slate-900 flex items-center justify-center text-white font-semibold">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <span className="text-base font-bold tracking-tight text-slate-900">
              SecurSpec
            </span>
            <span className="hidden sm:inline text-xs text-slate-400 ml-2 font-mono">
              v1.1.0 · Live Engine
            </span>
          </div>
        </div>

        {/* Zone 2: Navigation Links */}
        <nav className="hidden md:flex items-center gap-1">
          {tabs.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                  isActive
                    ? 'bg-slate-900 text-white shadow-xs'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </nav>

        {/* Zone 3: Primary Actions */}
        <div className="flex items-center gap-2">
          <button
            onClick={onExportPdf}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors whitespace-nowrap"
            title="Download formatted audit PDF"
          >
            <FileText className="w-3.5 h-3.5 text-slate-600" />
            <span>Export PDF</span>
          </button>
          <button
            onClick={onDownloadScript}
            className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-lg transition-colors whitespace-nowrap shadow-xs"
          >
            <Download className="w-3.5 h-3.5 text-slate-300" />
            <span>analyzer.py</span>
          </button>
        </div>
      </div>

      {/* Mobile Sub-Navigation Bar */}
      <div className="md:hidden flex items-center gap-1 px-4 py-2 border-t border-slate-100 overflow-x-auto no-scrollbar">
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-2.5 py-1 text-xs font-medium rounded-md whitespace-nowrap ${
                isActive ? 'bg-slate-900 text-white' : 'text-slate-600 bg-slate-50'
              }`}
            >
              {tab.label}
            </button>
          );
        })}
      </div>
    </header>
  );
};
