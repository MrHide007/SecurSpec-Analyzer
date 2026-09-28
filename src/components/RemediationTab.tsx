import React, { useState } from 'react';
import { RemediationGuide, MissingHeader } from '../types/analyzer';
import { Copy, Check, Server, FileCode, CheckCircle2 } from 'lucide-react';

interface RemediationTabProps {
  guide: RemediationGuide;
  missingHeaders: MissingHeader[];
  targetHostname: string;
}

export const RemediationTab: React.FC<RemediationTabProps> = ({
  guide,
  missingHeaders,
  targetHostname,
}) => {
  const [activeServer, setActiveServer] = useState<'nginx' | 'apache' | 'express' | 'caddy' | 'nextjs'>('nginx');
  const [copied, setCopied] = useState(false);

  const domain = targetHostname || 'example.com';

  const caddySnippet = `# Caddyfile for ${domain}
${domain} {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
        Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none';"
        Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
        -Server
    }
}`;

  const nextjsSnippet = `// next.config.mjs (Target: ${domain})
/** @type {import('next').NextConfig} */
const nextConfig = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' },
          { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none';" },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' }
        ],
      },
    ];
  },
};

export default nextConfig;`;

  const getActiveCode = () => {
    switch (activeServer) {
      case 'nginx':
        return guide.nginx_snippet;
      case 'apache':
        return guide.apache_snippet;
      case 'express':
        return guide.express_snippet;
      case 'caddy':
        return caddySnippet;
      case 'nextjs':
        return nextjsSnippet;
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(getActiveCode());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Intro */}
      <div className="bg-white border border-slate-200 rounded-lg p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 className="text-base font-bold text-slate-900">
              Server Remediation & Hardening Directives
            </h3>
            <p className="text-xs text-slate-600 mt-0.5">
              Customized configuration snippets for <strong className="font-mono text-slate-800">{domain}</strong> to eliminate identified header vulnerabilities.
            </p>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {missingHeaders.length} missing directives generated
          </span>
        </div>
      </div>

      {/* Code Editor Container */}
      <div className="bg-slate-900 rounded-lg overflow-hidden border border-slate-800">
        {/* Server Selector Bar */}
        <div className="flex flex-wrap items-center justify-between border-b border-slate-800 px-4 py-2.5 bg-slate-950">
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setActiveServer('nginx')}
              className={`px-3 py-1 text-xs font-mono font-medium rounded transition-colors ${
                activeServer === 'nginx'
                  ? 'bg-slate-800 text-emerald-400'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              nginx.conf
            </button>
            <button
              onClick={() => setActiveServer('apache')}
              className={`px-3 py-1 text-xs font-mono font-medium rounded transition-colors ${
                activeServer === 'apache'
                  ? 'bg-slate-800 text-emerald-400'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              .htaccess / apache
            </button>
            <button
              onClick={() => setActiveServer('express')}
              className={`px-3 py-1 text-xs font-mono font-medium rounded transition-colors ${
                activeServer === 'express'
                  ? 'bg-slate-800 text-emerald-400'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Express (Helmet)
            </button>
            <button
              onClick={() => setActiveServer('caddy')}
              className={`px-3 py-1 text-xs font-mono font-medium rounded transition-colors ${
                activeServer === 'caddy'
                  ? 'bg-slate-800 text-emerald-400'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Caddyfile
            </button>
            <button
              onClick={() => setActiveServer('nextjs')}
              className={`px-3 py-1 text-xs font-mono font-medium rounded transition-colors ${
                activeServer === 'nextjs'
                  ? 'bg-slate-800 text-emerald-400'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              next.config.mjs
            </button>
          </div>

          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-3 py-1 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded transition-colors font-mono"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy Config</span>
              </>
            )}
          </button>
        </div>

        {/* Code Content */}
        <pre className="p-4 text-xs font-mono text-slate-200 overflow-x-auto selection:bg-slate-700 leading-relaxed">
          <code>{getActiveCode()}</code>
        </pre>
      </div>

      {/* Defensive Checklist */}
      <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
        <h4 className="text-sm font-bold text-slate-900">
          Remediation Implementation Checklist for {domain}
        </h4>
        <div className="space-y-3 text-xs">
          <div className="flex items-start gap-3">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-slate-800">1. Deploy in staging first: </span>
              <span className="text-slate-600">
                Always test Content-Security-Policy (CSP) with <code className="font-mono bg-slate-100 px-1 rounded">Content-Security-Policy-Report-Only</code> before enforcing to prevent breaking third-party scripts.
              </span>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-slate-800">2. Verify HSTS subdomains: </span>
              <span className="text-slate-600">
                Enforcing <code className="font-mono bg-slate-100 px-1 rounded">includeSubDomains</code> applies HTTPS requirements to all subdomains of {domain}. Ensure internal microservices support HTTPS.
              </span>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-slate-800">3. Mask server identifiers: </span>
              <span className="text-slate-600">
                Turn off <code className="font-mono bg-slate-100 px-1 rounded">server_tokens</code> in Nginx and <code className="font-mono bg-slate-100 px-1 rounded">ServerSignature</code> in Apache to avoid broadcasting exact version numbers.
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
