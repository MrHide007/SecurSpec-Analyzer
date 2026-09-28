import React, { useState } from 'react';
import { Search, Loader2, Globe, Shield, AlertCircle, RefreshCw } from 'lucide-react';

interface AuditSearchBarProps {
  onAnalyze: (url: string, noSsl: boolean) => Promise<void>;
  isLoading: boolean;
  scanStage: string;
  currentUrl: string;
  errorMessage: string | null;
  onRetry: () => void;
}

const PRESET_DOMAINS = [
  'https://github.com',
  'https://example.com',
  'https://google.com',
  'https://cloudflare.com',
  'https://python.org',
];

export const AuditSearchBar: React.FC<AuditSearchBarProps> = ({
  onAnalyze,
  isLoading,
  scanStage,
  currentUrl,
  errorMessage,
  onRetry,
}) => {
  const [inputUrl, setInputUrl] = useState(currentUrl || 'https://example.com');
  const [noSsl, setNoSsl] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (inputUrl.trim() && !isLoading) {
      onAnalyze(inputUrl.trim(), noSsl);
    }
  };

  const handleSelectPreset = (preset: string) => {
    setInputUrl(preset);
    if (!isLoading) {
      onAnalyze(preset, noSsl);
    }
  };

  return (
    <div className="bg-white border-b border-slate-200 py-6 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto space-y-4">
        {/* Form */}
        <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
              <Globe className="w-4 h-4" />
            </div>
            <input
              type="text"
              value={inputUrl}
              onChange={(e) => setInputUrl(e.target.value)}
              placeholder="Enter domain or URL (e.g. https://yourdomain.com)"
              className="w-full pl-10 pr-4 py-2.5 text-sm bg-slate-50 border border-slate-300 rounded-lg text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-900 focus:bg-white font-mono transition-colors"
              disabled={isLoading}
            />
          </div>

          <div className="flex items-center gap-2">
            <label className="flex items-center gap-1.5 text-xs text-slate-600 cursor-pointer select-none px-2 py-2">
              <input
                type="checkbox"
                checked={noSsl}
                onChange={(e) => setNoSsl(e.target.checked)}
                className="rounded border-slate-300 text-slate-900 focus:ring-slate-900"
              />
              <span>Skip SSL</span>
            </label>

            <button
              type="submit"
              disabled={isLoading || !inputUrl.trim()}
              className="px-5 py-2.5 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors flex items-center justify-center gap-2 whitespace-nowrap shadow-xs"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-emerald-400" />
                  <span>Auditing...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>Audit Configuration</span>
                </>
              )}
            </button>
          </div>
        </form>

        {/* Live Stage Progress Indicator */}
        {isLoading && (
          <div className="bg-slate-900 text-white rounded-lg p-3.5 flex items-center justify-between gap-4 animate-in fade-in duration-200">
            <div className="flex items-center gap-3">
              <div className="relative flex items-center justify-center">
                <span className="animate-ping absolute inline-flex h-3 w-3 rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </div>
              <div className="text-xs font-mono">
                <span className="text-slate-400">Status: </span>
                <span className="text-emerald-400 font-semibold">{scanStage}</span>
              </div>
            </div>
            <div className="text-xs text-slate-400 font-mono hidden sm:block">
              Executing Python engine · Standard library SSL & HTTP analysis
            </div>
          </div>
        )}

        {/* User-friendly Error & Retry Prompt */}
        {errorMessage && !isLoading && (
          <div className="bg-rose-50 border border-rose-200 rounded-lg p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-rose-800 text-xs">
            <div className="flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
              <div className="space-y-0.5">
                <span className="font-semibold text-rose-900">Target Connection Issue</span>
                <p className="text-rose-700">{errorMessage}</p>
              </div>
            </div>
            <button
              onClick={onRetry}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-rose-900 bg-rose-100 hover:bg-rose-200 rounded-md transition-colors self-start sm:self-auto shrink-0"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry Scan</span>
            </button>
          </div>
        )}

        {/* Presets and Defensive Notice */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-slate-500">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-slate-400">Quick tests:</span>
            {PRESET_DOMAINS.map((preset) => (
              <button
                key={preset}
                type="button"
                onClick={() => handleSelectPreset(preset)}
                className="px-2 py-0.5 rounded text-xs bg-slate-100 hover:bg-slate-200 text-slate-700 transition-colors font-mono"
              >
                {preset.replace('https://', '')}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1.5 text-slate-500">
            <Shield className="w-3.5 h-3.5 text-slate-400" />
            <span>Scope: Passive HTTP response headers & local SSL handshake validation only</span>
          </div>
        </div>
      </div>
    </div>
  );
};
