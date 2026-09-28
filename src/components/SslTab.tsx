import React from 'react';
import { SslTlsReport } from '../types/analyzer';
import {
  Lock,
  Unlock,
  AlertTriangle,
  CheckCircle2,
  Calendar,
  Cpu,
  Layers,
  ShieldCheck,
  ShieldAlert,
} from 'lucide-react';

interface SslTabProps {
  ssl: SslTlsReport | null;
  targetUrl: string;
}

export const SslTab: React.FC<SslTabProps> = ({ ssl, targetUrl }) => {
  if (!ssl) {
    return (
      <div className="bg-white border border-slate-200 rounded-lg p-8 text-center text-slate-500 text-xs">
        No SSL/TLS report available. Target URL may use plain HTTP or SSL check was skipped.
      </div>
    );
  }

  if (!ssl.checked) {
    return (
      <div className="bg-amber-50 border border-amber-200 rounded-lg p-6 space-y-2">
        <div className="flex items-center gap-2 text-amber-800 font-semibold text-sm">
          <AlertTriangle className="w-5 h-5 text-amber-600" />
          <span>Unencrypted Plaintext HTTP Target</span>
        </div>
        <p className="text-xs text-amber-700">
          {ssl.reason || 'The target was queried over port 80 (HTTP) without TLS encryption.'}
        </p>
      </div>
    );
  }

  const daysLeft = ssl.days_remaining ?? 0;
  const progressPercent = Math.max(0, Math.min(100, Math.round((daysLeft / 365) * 100)));

  return (
    <div className="space-y-6">
      {/* Top Status Card */}
      <div className="bg-white border border-slate-200 rounded-lg p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div
              className={`w-12 h-12 rounded-lg flex items-center justify-center ${
                ssl.is_valid
                  ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                  : 'bg-rose-50 text-rose-700 border border-rose-200'
              }`}
            >
              {ssl.is_valid ? (
                <ShieldCheck className="w-6 h-6" />
              ) : (
                <ShieldAlert className="w-6 h-6" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-900">
                  {ssl.is_valid ? 'Valid TLS Certificate' : 'Certificate Verification Issue'}
                </h3>
                <span
                  className={`text-xs font-mono px-2 py-0.5 rounded border ${
                    ssl.is_valid
                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      : 'bg-rose-50 text-rose-700 border-rose-200'
                  }`}
                >
                  {ssl.tls_version || 'TLS'}
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                Validated via standard certificate authority trust store using Python standard library <code className="font-mono bg-slate-100 px-1 rounded">ssl</code>
              </p>
            </div>
          </div>

          <div className="text-right">
            <div className="text-xs text-slate-500">Days to Expiration</div>
            <div
              className={`text-2xl font-bold font-mono tabular-nums ${
                daysLeft > 30 ? 'text-slate-900' : daysLeft > 14 ? 'text-amber-600' : 'text-rose-600'
              }`}
            >
              {ssl.is_expired ? 'Expired' : `${daysLeft} days`}
            </div>
          </div>
        </div>

        {/* Expiration Progress Bar */}
        {!ssl.is_expired && daysLeft !== null && (
          <div className="mt-4 pt-4 border-t border-slate-100 space-y-1.5">
            <div className="flex justify-between text-xs text-slate-500 font-mono">
              <span>Valid From: {ssl.valid_from ? new Date(ssl.valid_from).toLocaleDateString() : 'N/A'}</span>
              <span>Expires: {ssl.valid_until ? new Date(ssl.valid_until).toLocaleDateString() : 'N/A'}</span>
            </div>
            <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${
                  daysLeft > 30 ? 'bg-emerald-600' : daysLeft > 14 ? 'bg-amber-500' : 'bg-rose-600'
                }`}
                style={{ width: `${progressPercent}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* SSL Error message if any */}
      {ssl.error && (
        <div className="bg-rose-50 border border-rose-200 rounded-lg p-4 text-xs text-rose-800 space-y-1">
          <div className="font-semibold">SSL Handshake / Trust Store Error:</div>
          <div className="font-mono">{ssl.error}</div>
        </div>
      )}

      {/* Grid of Details: Cipher Suite & Authority */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Card 1: Negotiated Cryptography */}
        <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
          <div className="flex items-center gap-2 text-slate-900 font-semibold text-sm">
            <Cpu className="w-4 h-4 text-slate-600" />
            <span>Negotiated Protocol & Cipher</span>
          </div>

          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-1.5 border-b border-slate-100">
              <span className="text-slate-500">Protocol:</span>
              <span className="font-mono font-medium text-slate-900">{ssl.tls_version || 'Unknown'}</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-100">
              <span className="text-slate-500">Cipher Suite:</span>
              <span className="font-mono font-medium text-slate-900">{ssl.cipher?.name || 'Unknown'}</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-100">
              <span className="text-slate-500">Key Length:</span>
              <span className="font-mono font-medium text-slate-900">{ssl.cipher?.bits ? `${ssl.cipher.bits} bits` : 'Unknown'}</span>
            </div>
            <div className="flex justify-between py-1.5">
              <span className="text-slate-500">Target Host & Port:</span>
              <span className="font-mono text-slate-900">{ssl.hostname}:{ssl.port || 443}</span>
            </div>
          </div>
        </div>

        {/* Card 2: Certificate Issuer (CA) */}
        <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
          <div className="flex items-center gap-2 text-slate-900 font-semibold text-sm">
            <Layers className="w-4 h-4 text-slate-600" />
            <span>Certificate Authority (Issuer)</span>
          </div>

          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-1.5 border-b border-slate-100">
              <span className="text-slate-500">Common Name (CN):</span>
              <span className="font-mono font-medium text-slate-900">
                {ssl.issuer?.commonName || 'N/A'}
              </span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-100">
              <span className="text-slate-500">Organization (O):</span>
              <span className="font-mono text-slate-900">
                {ssl.issuer?.organizationName || 'N/A'}
              </span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-slate-100">
              <span className="text-slate-500">Country (C):</span>
              <span className="font-mono text-slate-900">
                {ssl.issuer?.countryName || 'N/A'}
              </span>
            </div>
            <div className="flex justify-between py-1.5">
              <span className="text-slate-500">Subject CN:</span>
              <span className="font-mono text-slate-900">
                {ssl.subject?.commonName || ssl.hostname || 'N/A'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Card 3: Subject Alternative Names (SANs) */}
      {ssl.san && ssl.san.length > 0 && (
        <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold text-slate-900">
              Subject Alternative Names (SANs) · {ssl.san.length} hostnames
            </h4>
            <span className="text-xs text-slate-400">DNS identities covered by certificate</span>
          </div>
          <div className="flex flex-wrap gap-1.5 font-mono text-xs">
            {ssl.san.map((domain, i) => (
              <span
                key={i}
                className="bg-slate-50 border border-slate-200 text-slate-700 px-2 py-0.5 rounded"
              >
                {domain}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
