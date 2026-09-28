export interface Finding {
  id: string;
  severity: 'High' | 'Medium' | 'Low';
  title: string;
  detail: string;
  remediation: string;
}

export interface MissingHeader {
  header: string;
  name: string;
  severity: 'High' | 'Medium' | 'Low';
  category: string;
  description: string;
  remediation: string;
  recommendation: string;
  rfc: string;
  score_weight?: number;
}

export interface PresentHeader {
  header: string;
  name: string;
  value: string;
  category: string;
  notes: string[];
  is_optimal: boolean;
  score_weight?: number;
}

export interface DisclosureHeader {
  header: string;
  value: string;
}

export interface SslCipher {
  name: string;
  protocol: string;
  bits: number;
}

export interface SslTlsReport {
  checked: boolean;
  is_valid: boolean;
  hostname?: string;
  port?: number;
  tls_version?: string;
  cipher?: SslCipher;
  subject?: Record<string, string>;
  issuer?: Record<string, string>;
  san?: string[];
  valid_from?: string;
  valid_until?: string;
  days_remaining?: number;
  is_expired?: boolean;
  expires_soon?: boolean;
  findings?: Finding[];
  error?: string | null;
  reason?: string;
}

export interface HeadersReport {
  status_code: number | null;
  status_reason: string | null;
  redirect_url: string | null;
  raw_headers: Record<string, string>;
  missing_headers: MissingHeader[];
  present_headers: PresentHeader[];
  disclosure_headers: DisclosureHeader[];
  cookie_analysis: Array<{
    raw: string;
    secure: boolean;
    httponly: boolean;
    samesite: boolean;
  }>;
  findings: Finding[];
  error: string | null;
}

export interface RemediationGuide {
  nginx_snippet: string;
  apache_snippet: string;
  express_snippet: string;
}

export interface OwaspBreakdown {
  transport_security: number;
  injection_prevention: number;
  clickjacking: number;
  mime_sniffing: number;
  information_leakage: number;
  isolation_and_features: number;
}

export interface AuditReport {
  metadata: {
    analyzer: string;
    version: string;
    timestamp: string;
    target: {
      url: string;
      hostname: string;
      port: number;
      is_https: boolean;
    };
  };
  summary: {
    grade: string;
    owasp_compliance_score?: number;
    owasp_breakdown?: OwaspBreakdown;
    total_findings: number;
    high_severity: number;
    medium_severity: number;
    low_severity: number;
    headers_present_count: number;
    headers_missing_count: number;
    ssl_valid: boolean;
  };
  ssl_tls: SslTlsReport | null;
  headers: HeadersReport;
  findings: Finding[];
  remediation_guide: RemediationGuide;
}
