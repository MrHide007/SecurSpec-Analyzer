import React, { useState, useEffect } from 'react';
import { Terminal, Download, Copy, Check, Code2, Shield, Play } from 'lucide-react';

interface PythonCliTabProps {
  onDownloadScript: () => void;
  targetUrl: string;
}

export const PythonCliTab: React.FC<PythonCliTabProps> = ({ onDownloadScript, targetUrl }) => {
  const [pythonCode, setPythonCode] = useState<string>('Loading Python script...');
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/python-script')
      .then((res) => res.text())
      .then((data) => setPythonCode(data))
      .catch((err) => setPythonCode('# Error loading script: ' + String(err)));
  }, []);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const domain = targetUrl ? targetUrl.replace(/^https?:\/\//, '').replace(/\/$/, '') : 'example.com';

  return (
    <div className="space-y-6">
      {/* Intro */}
      <div className="bg-white border border-slate-200 rounded-lg p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h3 className="text-base font-bold text-slate-900">
              Standalone Python CLI Security Analyzer
            </h3>
            <p className="text-xs text-slate-600 mt-1 max-w-2xl">
              <code className="font-mono bg-slate-100 px-1 py-0.5 rounded">analyzer.py</code> is a completely self-contained Python 3 script. It requires <strong className="font-semibold text-slate-800">zero external pip dependencies</strong> and uses only the standard library (<code className="font-mono">urllib</code>, <code className="font-mono">ssl</code>, <code className="font-mono">socket</code>, <code className="font-mono">json</code>).
            </p>
          </div>
          <button
            onClick={onDownloadScript}
            className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-lg transition-colors whitespace-nowrap shadow-xs"
          >
            <Download className="w-4 h-4 text-emerald-400" />
            <span>Download analyzer.py</span>
          </button>
        </div>
      </div>

      {/* CLI Usage Examples */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
        <h4 className="text-sm font-bold text-slate-900 flex items-center gap-2">
          <Terminal className="w-4 h-4 text-slate-700" />
          <span>Quick CLI Commands</span>
        </h4>

        <div className="space-y-3">
          {/* Command 1 */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span>Human-readable terminal summary audit:</span>
              <button
                onClick={() => handleCopy(`python3 analyzer.py https://${domain}`, 'cmd1')}
                className="text-slate-700 hover:text-slate-900 font-mono text-xs flex items-center gap-1"
              >
                {copiedCmd === 'cmd1' ? (
                  <span className="text-emerald-600 font-sans">Copied</span>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span className="font-sans">Copy</span>
                  </>
                )}
              </button>
            </div>
            <pre className="bg-slate-900 text-slate-200 p-3 rounded font-mono text-xs overflow-x-auto select-all">
              <code>python3 analyzer.py https://{domain}</code>
            </pre>
          </div>

          {/* Command 2 */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span>Export localized JSON audit report:</span>
              <button
                onClick={() =>
                  handleCopy(`python3 analyzer.py https://${domain} --json > audit_report.json`, 'cmd2')
                }
                className="text-slate-700 hover:text-slate-900 font-mono text-xs flex items-center gap-1"
              >
                {copiedCmd === 'cmd2' ? (
                  <span className="text-emerald-600 font-sans">Copied</span>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span className="font-sans">Copy</span>
                  </>
                )}
              </button>
            </div>
            <pre className="bg-slate-900 text-slate-200 p-3 rounded font-mono text-xs overflow-x-auto select-all">
              <code>python3 analyzer.py https://{domain} --json &gt; audit_report.json</code>
            </pre>
          </div>

          {/* Command 3 */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span>Skip SSL verification (for plain HTTP / internal test environments) with custom timeout:</span>
              <button
                onClick={() =>
                  handleCopy(`python3 analyzer.py https://${domain} --no-ssl --timeout 12`, 'cmd3')
                }
                className="text-slate-700 hover:text-slate-900 font-mono text-xs flex items-center gap-1"
              >
                {copiedCmd === 'cmd3' ? (
                  <span className="text-emerald-600 font-sans">Copied</span>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span className="font-sans">Copy</span>
                  </>
                )}
              </button>
            </div>
            <pre className="bg-slate-900 text-slate-200 p-3 rounded font-mono text-xs overflow-x-auto select-all">
              <code>python3 analyzer.py https://{domain} --no-ssl --timeout 12</code>
            </pre>
          </div>
        </div>
      </div>

      {/* CI/CD Integration Card */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="text-sm font-bold text-slate-900">
              CI / CD Pipeline Automation (GitHub Actions)
            </h4>
            <p className="text-xs text-slate-500">
              Automatically audit headers on preview deployments and fail if High-severity headers are missing.
            </p>
          </div>
          <button
            onClick={() =>
              handleCopy(
                `- name: Audit Security Headers
  run: |
    python3 analyzer.py https://staging.example.com --json > report.json
    HIGH_COUNT=$(jq '.summary.high_severity' report.json)
    if [ "$HIGH_COUNT" -gt 0 ]; then
      echo "Failed: Found $HIGH_COUNT High-severity security header issues."
      exit 1
    fi`,
                'cicd'
              )
            }
            className="text-xs text-slate-700 hover:text-slate-900 flex items-center gap-1 font-medium"
          >
            {copiedCmd === 'cicd' ? (
              <span className="text-emerald-600">Copied</span>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy YAML</span>
              </>
            )}
          </button>
        </div>

        <pre className="bg-slate-900 text-slate-200 p-3.5 rounded font-mono text-xs overflow-x-auto">
{`- name: Audit Security Headers
  run: |
    python3 analyzer.py https://staging.example.com --json > report.json
    HIGH_COUNT=$(jq '.summary.high_severity' report.json)
    if [ "$HIGH_COUNT" -gt 0 ]; then
      echo "Failed: Found $HIGH_COUNT High-severity security header issues."
      exit 1
    fi`}
        </pre>
      </div>

      {/* Python Source Code Viewer */}
      <div className="bg-slate-900 rounded-lg overflow-hidden border border-slate-800">
        <div className="flex items-center justify-between px-4 py-2.5 bg-slate-950 border-b border-slate-800 text-xs font-mono text-slate-400">
          <div className="flex items-center gap-2">
            <Code2 className="w-4 h-4 text-emerald-400" />
            <span className="text-slate-200 font-medium">analyzer.py</span>
            <span>· Standard Library Only</span>
          </div>

          <button
            onClick={() => handleCopy(pythonCode, 'pycode')}
            className="flex items-center gap-1 text-slate-300 hover:text-white"
          >
            {copiedCmd === 'pycode' ? (
              <span className="text-emerald-400 font-sans">Copied Script</span>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span className="font-sans">Copy Source</span>
              </>
            )}
          </button>
        </div>

        <pre className="p-4 text-xs font-mono text-slate-200 max-h-[500px] overflow-y-auto overflow-x-auto leading-relaxed selection:bg-slate-700">
          <code>{pythonCode}</code>
        </pre>
      </div>
    </div>
  );
};
