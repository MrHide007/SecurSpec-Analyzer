import { AuditReport } from '../types/analyzer';

export const INITIAL_SAMPLE_REPORT: AuditReport = {
  metadata: {
    analyzer: "Python Web Configuration & Header Security Analyzer",
    version: "1.1.0",
    timestamp: new Date().toISOString(),
    target: {
      url: "https://example.com/",
      hostname: "example.com",
      port: 443,
      is_https: true
    }
  },
  summary: {
    grade: "D",
    owasp_compliance_score: 30,
    owasp_breakdown: {
      transport_security: 10,
      injection_prevention: 0,
      clickjacking: 0,
      mime_sniffing: 0,
      information_leakage: 0,
      isolation_and_features: 0
    },
    total_findings: 9,
    high_severity: 2,
    medium_severity: 2,
    low_severity: 5,
    headers_present_count: 0,
    headers_missing_count: 8,
    ssl_valid: true
  },
  ssl_tls: {
    checked: true,
    is_valid: true,
    hostname: "example.com",
    port: 443,
    tls_version: "TLSv1.3",
    cipher: {
      name: "TLS_AES_256_GCM_SHA384",
      protocol: "TLSv1.3",
      bits: 256
    },
    subject: {
      commonName: "example.com"
    },
    issuer: {
      countryName: "US",
      organizationName: "DigiCert Inc",
      commonName: "DigiCert Global G2 TLS RSA SHA256 2020 CA1"
    },
    san: ["example.com", "www.example.com"],
    valid_from: "2026-01-15T00:00:00+00:00",
    valid_until: "2027-01-16T23:59:59+00:00",
    days_remaining: 110,
    is_expired: false,
    expires_soon: false,
    findings: [],
    error: null
  },
  headers: {
    status_code: 200,
    status_reason: "OK",
    redirect_url: null,
    raw_headers: {
      "content-encoding": "gzip",
      "accept-ranges": "bytes",
      "age": "495514",
      "cache-control": "max-age=604800",
      "content-type": "text/html; charset=UTF-8",
      "date": new Date().toUTCString(),
      "etag": "\"3147526947\"",
      "expires": new Date(Date.now() + 604800000).toUTCString(),
      "last-modified": "Thu, 17 Oct 2025 07:18:26 GMT",
      "server": "ECS (dcb/7F3B)",
      "vary": "Accept-Encoding",
      "x-cache": "HIT"
    },
    missing_headers: [
      {
        header: "Strict-Transport-Security",
        name: "Strict-Transport-Security (HSTS)",
        severity: "High",
        category: "Transport Security",
        description: "Enforces secure (HTTPS) connections to the server and prevents downgrade attacks and cookie-hijacking.",
        remediation: "Configure your web server to return 'max-age=31536000; includeSubDomains; preload'.",
        recommendation: "max-age=31536000; includeSubDomains; preload",
        rfc: "RFC 6797",
        score_weight: 25
      },
      {
        header: "Content-Security-Policy",
        name: "Content-Security-Policy (CSP)",
        severity: "High",
        category: "Injection Prevention",
        description: "Restricts resources (scripts, images, stylesheets) that the browser is allowed to load for a given page, mitigating XSS and data injection.",
        remediation: "Define a robust policy such as \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';\". Avoid 'unsafe-inline' without nonces or hashes.",
        recommendation: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; base-uri 'self';",
        rfc: "W3C CSP Level 3",
        score_weight: 25
      },
      {
        header: "X-Frame-Options",
        name: "X-Frame-Options",
        severity: "Medium",
        category: "Clickjacking Defense",
        description: "Controls whether a browser should be allowed to render a page in a <frame>, <iframe>, <embed>, or <object>, protecting against UI redressing (Clickjacking).",
        remediation: "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'. Alternatively, configure 'frame-ancestors' directive in Content-Security-Policy.",
        recommendation: "DENY",
        rfc: "RFC 7034",
        score_weight: 15
      },
      {
        header: "X-Content-Type-Options",
        name: "X-Content-Type-Options",
        severity: "Medium",
        category: "MIME Sniffing Defense",
        description: "Prevents browsers from MIME-sniffing a response away from the declared Content-Type, reducing exposure to drive-by malicious file uploads.",
        remediation: "Set X-Content-Type-Options to 'nosniff'.",
        recommendation: "nosniff",
        rfc: "Fetch Living Standard",
        score_weight: 10
      },
      {
        header: "Referrer-Policy",
        name: "Referrer-Policy",
        severity: "Low",
        category: "Information Leakage",
        description: "Controls how much referrer information (via the Referer header) should be included with requests sent from your site.",
        remediation: "Set to 'strict-origin-when-cross-origin' or 'no-referrer'.",
        recommendation: "strict-origin-when-cross-origin",
        rfc: "W3C Referrer Policy",
        score_weight: 10
      },
      {
        header: "Permissions-Policy",
        name: "Permissions-Policy",
        severity: "Low",
        category: "Feature Governance",
        description: "Allows site administrators to restrict or delegate access to browser features and APIs (such as camera, microphone, geolocation, payment).",
        remediation: "Restrict unused browser APIs, e.g., 'camera=(), microphone=(), geolocation=(), payment=()'.",
        recommendation: "camera=(), microphone=(), geolocation=(), payment=()",
        rfc: "W3C Permissions Policy",
        score_weight: 5
      },
      {
        header: "Cross-Origin-Opener-Policy",
        name: "Cross-Origin-Opener-Policy (COOP)",
        severity: "Low",
        category: "Cross-Origin Isolation",
        description: "Ensures a top-level document does not share a browsing context group with cross-origin documents, isolating the execution context.",
        remediation: "Set Cross-Origin-Opener-Policy to 'same-origin'.",
        recommendation: "same-origin",
        rfc: "HTML Living Standard § 7.3.3",
        score_weight: 5
      },
      {
        header: "Cross-Origin-Resource-Policy",
        name: "Cross-Origin-Resource-Policy (CORP)",
        severity: "Low",
        category: "Cross-Origin Isolation",
        description: "Blocks others from loading your resources into their pages (e.g., images or scripts), mitigating Spectre-like side-channel attacks.",
        remediation: "Set Cross-Origin-Resource-Policy to 'same-origin' or 'same-site'.",
        recommendation: "same-origin",
        rfc: "Fetch Living Standard",
        score_weight: 5
      }
    ],
    present_headers: [],
    disclosure_headers: [
      {
        header: "server",
        value: "ECS (dcb/7F3B)"
      }
    ],
    cookie_analysis: [],
    findings: [],
    error: null
  },
  findings: [
    {
      id: "missing_strict-transport-security",
      severity: "High",
      title: "Missing Security Header: Strict-Transport-Security",
      detail: "Enforces secure (HTTPS) connections to the server and prevents downgrade attacks and cookie-hijacking.",
      remediation: "Configure your web server to return 'max-age=31536000; includeSubDomains; preload'."
    },
    {
      id: "missing_content-security-policy",
      severity: "High",
      title: "Missing Security Header: Content-Security-Policy",
      detail: "Restricts resources (scripts, images, stylesheets) that the browser is allowed to load for a given page, mitigating XSS and data injection.",
      remediation: "Define a robust policy such as \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';\"."
    },
    {
      id: "missing_x-frame-options",
      severity: "Medium",
      title: "Missing Security Header: X-Frame-Options",
      detail: "Controls whether a browser should be allowed to render a page in a <frame>, <iframe>, <embed>, or <object>, protecting against UI redressing (Clickjacking).",
      remediation: "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'."
    },
    {
      id: "missing_x-content-type-options",
      severity: "Medium",
      title: "Missing Security Header: X-Content-Type-Options",
      detail: "Prevents browsers from MIME-sniffing a response away from the declared Content-Type, reducing exposure to drive-by malicious file uploads.",
      remediation: "Set X-Content-Type-Options to 'nosniff'."
    },
    {
      id: "missing_referrer-policy",
      severity: "Low",
      title: "Missing Security Header: Referrer-Policy",
      detail: "Controls how much referrer information (via the Referer header) should be included with requests sent from your site.",
      remediation: "Set to 'strict-origin-when-cross-origin' or 'no-referrer'."
    },
    {
      id: "missing_permissions-policy",
      severity: "Low",
      title: "Missing Security Header: Permissions-Policy",
      detail: "Allows site administrators to restrict or delegate access to browser features and APIs.",
      remediation: "Restrict unused browser APIs, e.g., 'camera=(), microphone=(), geolocation=(), payment=()'."
    },
    {
      id: "missing_cross-origin-opener-policy",
      severity: "Low",
      title: "Missing Security Header: Cross-Origin-Opener-Policy",
      detail: "Ensures a top-level document does not share a browsing context group with cross-origin documents.",
      remediation: "Set Cross-Origin-Opener-Policy to 'same-origin'."
    },
    {
      id: "missing_cross-origin-resource-policy",
      severity: "Low",
      title: "Missing Security Header: Cross-Origin-Resource-Policy",
      detail: "Blocks others from loading your resources into their pages.",
      remediation: "Set Cross-Origin-Resource-Policy to 'same-origin' or 'same-site'."
    },
    {
      id: "info_disclosure_server",
      severity: "Low",
      title: "Information Disclosure Header: server",
      detail: "Server revealed version/technology metadata: 'ECS (dcb/7F3B)'.",
      remediation: "Disable or mask the 'server' response header in your web server/reverse proxy configuration."
    }
  ],
  remediation_guide: {
    nginx_snippet: `# Add inside your nginx server { ... } block:
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none';" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
# Hide server version banner:
server_tokens off;`,
    apache_snippet: `# Place inside <VirtualHost *:443> or .htaccess (requires mod_headers):
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none';"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
    Header unset X-Powered-By
</IfModule>
ServerSignature Off`,
    express_snippet: `// npm install helmet
import helmet from 'helmet';
import express from 'express';

const app = express();

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  })
);`
  }
};
