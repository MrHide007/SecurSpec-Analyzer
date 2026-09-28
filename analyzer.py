#!/usr/bin/env python3
"""
Python Web Configuration & Header Security Analyzer
Defensive, passive HTTP response header and SSL/TLS certificate auditor.
Uses standard library (urllib, ssl, socket, json, datetime) with robust fallback handling.
"""

import argparse
import datetime
import json
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


SECURITY_HEADERS_SPEC = {
    "Strict-Transport-Security": {
        "name": "Strict-Transport-Security (HSTS)",
        "severity": "High",
        "description": "Enforces secure (HTTPS) connections to the server and prevents downgrade attacks and cookie-hijacking.",
        "remediation": "Configure your web server to return 'max-age=31536000; includeSubDomains; preload'.",
        "recommendation": "max-age=31536000; includeSubDomains; preload",
        "rfc": "RFC 6797",
        "category": "Transport Security",
        "score_weight": 25,
    },
    "Content-Security-Policy": {
        "name": "Content-Security-Policy (CSP)",
        "severity": "High",
        "description": "Restricts resources (scripts, images, stylesheets) that the browser is allowed to load for a given page, mitigating XSS and data injection.",
        "remediation": "Define a robust policy such as \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';\". Avoid 'unsafe-inline' without nonces or hashes.",
        "recommendation": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; base-uri 'self';",
        "rfc": "W3C CSP Level 3",
        "category": "Injection Prevention",
        "score_weight": 25,
    },
    "X-Frame-Options": {
        "name": "X-Frame-Options",
        "severity": "Medium",
        "description": "Controls whether a browser should be allowed to render a page in a <frame>, <iframe>, <embed>, or <object>, protecting against UI redressing (Clickjacking).",
        "remediation": "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'. Alternatively, configure 'frame-ancestors' directive in Content-Security-Policy.",
        "recommendation": "DENY",
        "rfc": "RFC 7034",
        "category": "Clickjacking Defense",
        "score_weight": 15,
    },
    "X-Content-Type-Options": {
        "name": "X-Content-Type-Options",
        "severity": "Medium",
        "description": "Prevents browsers from MIME-sniffing a response away from the declared Content-Type, reducing exposure to drive-by malicious file uploads.",
        "remediation": "Set X-Content-Type-Options to 'nosniff'.",
        "recommendation": "nosniff",
        "rfc": "Fetch Living Standard",
        "category": "MIME Sniffing Defense",
        "score_weight": 10,
    },
    "Referrer-Policy": {
        "name": "Referrer-Policy",
        "severity": "Low",
        "description": "Controls how much referrer information (via the Referer header) should be included with requests sent from your site.",
        "remediation": "Set to 'strict-origin-when-cross-origin' or 'no-referrer'.",
        "recommendation": "strict-origin-when-cross-origin",
        "rfc": "W3C Referrer Policy",
        "category": "Information Leakage",
        "score_weight": 10,
    },
    "Permissions-Policy": {
        "name": "Permissions-Policy",
        "severity": "Low",
        "description": "Allows site administrators to restrict or delegate access to browser features and APIs (such as camera, microphone, geolocation, payment).",
        "remediation": "Restrict unused browser APIs, e.g., 'camera=(), microphone=(), geolocation=(), payment=()'.",
        "recommendation": "camera=(), microphone=(), geolocation=(), payment=()",
        "rfc": "W3C Permissions Policy",
        "category": "Feature Governance",
        "score_weight": 5,
    },
    "Cross-Origin-Opener-Policy": {
        "name": "Cross-Origin-Opener-Policy (COOP)",
        "severity": "Low",
        "description": "Ensures a top-level document does not share a browsing context group with cross-origin documents, isolating the execution context.",
        "remediation": "Set Cross-Origin-Opener-Policy to 'same-origin'.",
        "recommendation": "same-origin",
        "rfc": "HTML Living Standard § 7.3.3",
        "category": "Cross-Origin Isolation",
        "score_weight": 5,
    },
    "Cross-Origin-Resource-Policy": {
        "name": "Cross-Origin-Resource-Policy (CORP)",
        "severity": "Low",
        "description": "Blocks others from loading your resources into their pages (e.g., images or scripts), mitigating Spectre-like side-channel attacks.",
        "remediation": "Set Cross-Origin-Resource-Policy to 'same-origin' or 'same-site'.",
        "recommendation": "same-origin",
        "rfc": "Fetch Living Standard",
        "category": "Cross-Origin Isolation",
        "score_weight": 5,
    }
}

INFORMATION_DISCLOSURE_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-backend-server"
]


def normalize_url(raw_url: str) -> Tuple[str, str, int, bool]:
    """Parse and normalize target URL, returning (full_url, hostname, port, is_https)."""
    raw_url = raw_url.strip()
    if not (raw_url.startswith("http://") or raw_url.startswith("https://")):
        raw_url = "https://" + raw_url

    parsed = urllib.parse.urlsplit(raw_url)
    hostname = parsed.hostname or "localhost"
    is_https = parsed.scheme.lower() == "https"
    port = parsed.port if parsed.port is not None else (443 if is_https else 80)
    
    # Reassemble normalized URL
    path = parsed.path if parsed.path else "/"
    full_url = f"{parsed.scheme}://{parsed.netloc}{path}"
    if parsed.query:
        full_url += f"?{parsed.query}"
        
    return full_url, hostname, port, is_https


def inspect_ssl_tls(hostname: str, port: int = 443, timeout: float = 8.0) -> Dict[str, Any]:
    """
    Check SSL/TLS server certificate validity, expiration, issuer, subject, and ciphers
    using Python's standard library `ssl` and `socket`.
    """
    ssl_result: Dict[str, Any] = {
        "checked": True,
        "is_valid": False,
        "hostname": hostname,
        "port": port,
        "tls_version": None,
        "cipher": None,
        "subject": {},
        "issuer": {},
        "san": [],
        "valid_from": None,
        "valid_until": None,
        "days_remaining": None,
        "is_expired": False,
        "expires_soon": False,
        "findings": [],
        "error": None
    }

    ctx = ssl.create_default_context()
    # Verify hostname with SNI
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher_info = ssock.cipher()
                tls_version = ssock.version()

                ssl_result["tls_version"] = tls_version
                if cipher_info:
                    ssl_result["cipher"] = {
                        "name": cipher_info[0],
                        "protocol": cipher_info[1],
                        "bits": cipher_info[2]
                    }

                if cert:
                    # Parse subject
                    for item in cert.get("subject", ()):
                        for key, value in item:
                            ssl_result["subject"][key] = value

                    # Parse issuer
                    for item in cert.get("issuer", ()):
                        for key, value in item:
                            ssl_result["issuer"][key] = value

                    # Parse SANs (Subject Alternative Names)
                    sans = []
                    for key, value in cert.get("subjectAltName", ()):
                        if key.lower() == "dns":
                            sans.append(value)
                    ssl_result["san"] = sans

                    # Parse dates
                    not_before_str = cert.get("notBefore")
                    not_after_str = cert.get("notAfter")
                    date_format = "%b %d %H:%M:%S %Y %Z"

                    if not_before_str:
                        try:
                            not_before_dt = datetime.datetime.strptime(not_before_str, date_format).replace(tzinfo=datetime.timezone.utc)
                            ssl_result["valid_from"] = not_before_dt.isoformat()
                        except Exception:
                            pass

                    if not_after_str:
                        try:
                            not_after_dt = datetime.datetime.strptime(not_after_str, date_format).replace(tzinfo=datetime.timezone.utc)
                            ssl_result["valid_until"] = not_after_dt.isoformat()
                            
                            now = datetime.datetime.now(datetime.timezone.utc)
                            diff = not_after_dt - now
                            days_left = diff.days

                            ssl_result["days_remaining"] = days_left
                            ssl_result["is_expired"] = days_left < 0
                            ssl_result["expires_soon"] = 0 <= days_left <= 30

                            if days_left < 0:
                                ssl_result["findings"].append({
                                    "id": "ssl_expired",
                                    "severity": "High",
                                    "title": "SSL/TLS Certificate is Expired",
                                    "detail": f"The certificate expired on {not_after_dt.strftime('%Y-%m-%d')} ({abs(days_left)} days ago).",
                                    "remediation": "Renew and re-install the TLS certificate immediately using Let's Encrypt (Certbot) or your Certificate Authority."
                                })
                            elif days_left <= 14:
                                ssl_result["findings"].append({
                                    "id": "ssl_expires_critical",
                                    "severity": "High",
                                    "title": "SSL/TLS Certificate Expiring Imminently",
                                    "detail": f"The certificate will expire in {days_left} days on {not_after_dt.strftime('%Y-%m-%d')}.",
                                    "remediation": "Initiate automated certificate renewal via ACME / Certbot to avoid service interruption."
                                })
                            elif days_left <= 30:
                                ssl_result["findings"].append({
                                    "id": "ssl_expires_soon",
                                    "severity": "Medium",
                                    "title": "SSL/TLS Certificate Expiring Within 30 Days",
                                    "detail": f"Certificate valid for {days_left} more days.",
                                    "remediation": "Verify automated renewal triggers are scheduled."
                                })
                        except Exception:
                            pass

                # Check TLS protocol version
                if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    ssl_result["findings"].append({
                        "id": "ssl_deprecated_protocol",
                        "severity": "High",
                        "title": f"Deprecated TLS Protocol ({tls_version})",
                        "detail": f"The server negotiated {tls_version}, which is cryptographically deprecated per RFC 8996.",
                        "remediation": "Disable TLS 1.0/1.1 in your web server configuration and require TLSv1.2 or TLSv1.3."
                    })

                ssl_result["is_valid"] = (not ssl_result["is_expired"]) and (len([f for f in ssl_result["findings"] if f["severity"] == "High"]) == 0)

    except ssl.SSLCertVerificationError as e:
        ssl_result["is_valid"] = False
        ssl_result["error"] = str(e)
        ssl_result["findings"].append({
            "id": "ssl_verification_failed",
            "severity": "High",
            "title": "SSL/TLS Certificate Verification Failed",
            "detail": f"Peer certificate cannot be validated by standard trust store: {e.verify_message or str(e)}.",
            "remediation": "Ensure the server provides the complete intermediate certificate chain and that the certificate matches the domain hostname."
        })
    except socket.timeout:
        ssl_result["error"] = "Connection timed out during SSL handshake."
        ssl_result["findings"].append({
            "id": "ssl_timeout",
            "severity": "Medium",
            "title": "SSL Handshake Timeout",
            "detail": f"Handshake with {hostname}:{port} exceeded {timeout}s timeout.",
            "remediation": "Check firewall rules, network latency, or server port configuration."
        })
    except Exception as e:
        ssl_result["error"] = str(e)
        ssl_result["findings"].append({
            "id": "ssl_handshake_error",
            "severity": "Medium",
            "title": "SSL Connection Error",
            "detail": str(e),
            "remediation": "Verify server accepts HTTPS connections on port 443 with valid TLS."
        })

    return ssl_result


def analyze_http_headers(url: str, timeout: float = 8.0) -> Dict[str, Any]:
    """
    Perform a defensive HTTP request and inspect headers against security best practices.
    Supports standard SSL verification and automatic fallback for self-signed testing certs.
    """
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 SecurSpec-ConfigAnalyzer/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9"
        },
        method="GET"
    )

    result: Dict[str, Any] = {
        "status_code": None,
        "status_reason": None,
        "redirect_url": None,
        "raw_headers": {},
        "missing_headers": [],
        "present_headers": [],
        "disclosure_headers": [],
        "cookie_analysis": [],
        "findings": [],
        "error": None
    }

    response = None
    try:
        # First attempt: standard strict SSL validation
        response = urllib.request.urlopen(req, timeout=timeout)
    except ssl.SSLCertVerificationError:
        # Fallback: inspect headers even if local root CA chain fails for dev/self-signed certs
        try:
            unverified_ctx = ssl._create_unverified_context()
            response = urllib.request.urlopen(req, context=unverified_ctx, timeout=timeout)
        except Exception as fallback_err:
            result["error"] = f"SSL Handshake failed: {str(fallback_err)}"
            return result
    except urllib.error.HTTPError as e:
        # Even on 4xx/5xx, security headers should still be present
        result["status_code"] = e.code
        result["status_reason"] = e.reason
        raw_headers = {}
        if hasattr(e, "headers") and e.headers:
            for k, v in e.headers.items():
                raw_headers[k] = v
        result["raw_headers"] = raw_headers
    except urllib.error.URLError as e:
        result["error"] = f"Failed to connect to target URL: {e.reason}"
        return result
    except Exception as e:
        result["error"] = f"Unexpected request failure: {str(e)}"
        return result

    if response is not None:
        try:
            result["status_code"] = response.status
            result["status_reason"] = response.reason
            if response.geturl() != url:
                result["redirect_url"] = response.geturl()

            raw_headers = {}
            for k, v in response.headers.items():
                raw_headers[k] = v
            result["raw_headers"] = raw_headers
        finally:
            response.close()

    # Standardize header keys in lowercase for lookup
    headers_lower = {k.lower(): (k, v) for k, v in result["raw_headers"].items()}

    # 1. Audit core security headers
    for header_name, spec in SECURITY_HEADERS_SPEC.items():
        h_lower = header_name.lower()
        if h_lower in headers_lower:
            actual_key, value = headers_lower[h_lower]
            eval_notes = []

            # Inspect CSP quality
            if header_name == "Content-Security-Policy":
                if "unsafe-inline" in value:
                    eval_notes.append("Policy includes 'unsafe-inline' which reduces XSS protection unless paired with nonces/hashes.")
                if "unsafe-eval" in value:
                    eval_notes.append("Policy includes 'unsafe-eval' which allows string evaluation like eval().")
                if "default-src" not in value and "script-src" not in value:
                    eval_notes.append("Neither 'default-src' nor 'script-src' directive specified.")
            
            # Inspect HSTS quality
            elif header_name == "Strict-Transport-Security":
                if "max-age" in value.lower():
                    try:
                        parts = [p.strip() for p in value.split(";")]
                        for p in parts:
                            if p.lower().startswith("max-age="):
                                ma_val = int(p.split("=")[1])
                                if ma_val < 15552000:
                                    eval_notes.append(f"HSTS max-age ({ma_val}s) is shorter than recommended 180 days (15552000s).")
                    except Exception:
                        pass
                if "includesubdomains" not in value.lower():
                    eval_notes.append("Consider adding 'includeSubDomains' to protect all subdomains.")

            result["present_headers"].append({
                "header": header_name,
                "name": spec["name"],
                "value": value,
                "category": spec["category"],
                "notes": eval_notes,
                "is_optimal": len(eval_notes) == 0,
                "score_weight": spec.get("score_weight", 10)
            })
        else:
            result["missing_headers"].append({
                "header": header_name,
                "name": spec["name"],
                "severity": spec["severity"],
                "category": spec["category"],
                "description": spec["description"],
                "remediation": spec["remediation"],
                "recommendation": spec["recommendation"],
                "rfc": spec["rfc"],
                "score_weight": spec.get("score_weight", 10)
            })
            result["findings"].append({
                "id": f"missing_{h_lower}",
                "severity": spec["severity"],
                "title": f"Missing Security Header: {header_name}",
                "detail": spec["description"],
                "remediation": spec["remediation"]
            })

    # 2. Check for information disclosure headers
    for disc in INFORMATION_DISCLOSURE_HEADERS:
        if disc in headers_lower:
            actual_key, value = headers_lower[disc]
            result["disclosure_headers"].append({
                "header": actual_key,
                "value": value
            })
            result["findings"].append({
                "id": f"info_disclosure_{disc}",
                "severity": "Low",
                "title": f"Information Disclosure Header: {actual_key}",
                "detail": f"Server revealed version/technology metadata: '{value}'.",
                "remediation": f"Disable or mask the '{actual_key}' response header in your web server/reverse proxy configuration."
            })

    # 3. Check cookies for secure attributes
    for k, v in result["raw_headers"].items():
        if k.lower() == "set-cookie":
            cookie_str = str(v)
            flags = {
                "raw": cookie_str,
                "secure": "secure" in cookie_str.lower(),
                "httponly": "httponly" in cookie_str.lower(),
                "samesite": "samesite" in cookie_str.lower()
            }
            result["cookie_analysis"].append(flags)
            missing_flags = []
            if not flags["secure"]:
                missing_flags.append("'Secure'")
            if not flags["httponly"]:
                missing_flags.append("'HttpOnly'")
            if not flags["samesite"]:
                missing_flags.append("'SameSite'")

            if missing_flags:
                result["findings"].append({
                    "id": "cookie_missing_flags",
                    "severity": "Medium",
                    "title": f"Insecure Cookie Flags: Missing {', '.join(missing_flags)}",
                    "detail": "Cookies transmitted without Secure/HttpOnly/SameSite flags are susceptible to interception and CSRF/XSS exploitation.",
                    "remediation": "Update cookie configuration to enforce Secure; HttpOnly; SameSite=Lax (or Strict)."
                })

    return result


def compute_compliance_and_grade(
    present_headers: List[Dict[str, Any]],
    missing_headers: List[Dict[str, Any]],
    all_findings: List[Dict[str, Any]],
    ssl_report: Optional[Dict[str, Any]],
    is_https: bool
) -> Tuple[int, str, Dict[str, Any]]:
    """
    Computes standard OWASP Header Compliance Score (0 - 100) and Overall Security Grade (A+ to F).
    Follows OWASP Secure Headers Project weighted compliance criteria.
    """
    score = 0
    total_weights = 100

    # Score breakdown by OWASP categories
    breakdown = {
        "transport_security": 0,    # Max 25 (HSTS + SSL)
        "injection_prevention": 0,  # Max 25 (CSP)
        "clickjacking": 0,          # Max 15 (X-Frame-Options)
        "mime_sniffing": 0,         # Max 10 (X-Content-Type-Options)
        "information_leakage": 0,   # Max 10 (Referrer-Policy & No Leak)
        "isolation_and_features": 0 # Max 15 (Permissions-Policy, COOP, CORP)
    }

    present_dict = {h["header"]: h for h in present_headers}

    # 1. Transport Security (Max 25)
    if is_https:
        if ssl_report and ssl_report.get("is_valid", False):
            base_tls = 10
            if "Strict-Transport-Security" in present_dict:
                hsts = present_dict["Strict-Transport-Security"]
                base_tls += 15 if hsts.get("is_optimal", True) else 10
            breakdown["transport_security"] = min(25, base_tls)
        else:
            breakdown["transport_security"] = 5
    else:
        breakdown["transport_security"] = 0

    # 2. Injection Prevention (CSP - Max 25)
    if "Content-Security-Policy" in present_dict:
        csp = present_dict["Content-Security-Policy"]
        if csp.get("is_optimal", True):
            breakdown["injection_prevention"] = 25
        else:
            breakdown["injection_prevention"] = 15
    else:
        breakdown["injection_prevention"] = 0

    # 3. Clickjacking (X-Frame-Options - Max 15)
    if "X-Frame-Options" in present_dict:
        breakdown["clickjacking"] = 15
    elif "Content-Security-Policy" in present_dict and "frame-ancestors" in present_dict["Content-Security-Policy"]["value"]:
        breakdown["clickjacking"] = 15
    else:
        breakdown["clickjacking"] = 0

    # 4. MIME Sniffing (X-Content-Type-Options - Max 10)
    if "X-Content-Type-Options" in present_dict:
        breakdown["mime_sniffing"] = 10
    else:
        breakdown["mime_sniffing"] = 0

    # 5. Information Leakage (Referrer-Policy - Max 10)
    if "Referrer-Policy" in present_dict:
        breakdown["information_leakage"] = 10
    else:
        breakdown["information_leakage"] = 0

    # 6. Feature & Origin Isolation (Max 15)
    iso_score = 0
    if "Permissions-Policy" in present_dict:
        iso_score += 5
    if "Cross-Origin-Opener-Policy" in present_dict:
        iso_score += 5
    if "Cross-Origin-Resource-Policy" in present_dict:
        iso_score += 5
    breakdown["isolation_and_features"] = iso_score

    score = sum(breakdown.values())

    # Grade determination (A+ to F)
    has_hsts = "Strict-Transport-Security" in present_dict
    has_csp = "Content-Security-Policy" in present_dict
    has_xfo = "X-Frame-Options" in present_dict
    ssl_ok = (ssl_report and ssl_report.get("is_valid", False)) if is_https else False

    if score >= 95 and ssl_ok and has_hsts and has_csp and has_xfo:
        grade = "A+"
    elif score >= 85 and ssl_ok and (has_hsts or has_csp):
        grade = "A"
    elif score >= 75 and ssl_ok:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    # Plain HTTP cap
    if not is_https:
        grade = "F"

    return score, grade, breakdown


def run_audit(url: str, check_ssl: bool = True, timeout: float = 8.0) -> Dict[str, Any]:
    """Execute complete web configuration & security header audit."""
    full_url, hostname, port, is_https = normalize_url(url)
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    header_report = analyze_http_headers(full_url, timeout=timeout)
    
    ssl_report = None
    if check_ssl:
        if is_https:
            ssl_report = inspect_ssl_tls(hostname, port, timeout=timeout)
        else:
            ssl_report = {
                "checked": False,
                "is_valid": False,
                "reason": "Target URL uses unencrypted plain HTTP (port 80).",
                "findings": [{
                    "id": "unencrypted_http",
                    "severity": "High",
                    "title": "Plaintext HTTP Connection",
                    "detail": "Target website was queried over HTTP without TLS transport encryption.",
                    "remediation": "Migrate your web application to HTTPS with a trusted TLS certificate."
                }]
            }

    # Aggregate all findings
    all_findings = []
    if header_report.get("findings"):
        all_findings.extend(header_report["findings"])
    if ssl_report and ssl_report.get("findings"):
        all_findings.extend(ssl_report["findings"])

    high_count = sum(1 for f in all_findings if f["severity"] == "High")
    med_count = sum(1 for f in all_findings if f["severity"] == "Medium")
    low_count = sum(1 for f in all_findings if f["severity"] == "Low")

    owasp_score, grade, breakdown = compute_compliance_and_grade(
        header_report.get("present_headers", []),
        header_report.get("missing_headers", []),
        all_findings,
        ssl_report,
        is_https
    )

    audit_report = {
        "metadata": {
            "analyzer": "Python Web Configuration & Header Security Analyzer",
            "version": "1.1.0",
            "timestamp": timestamp,
            "target": {
                "url": full_url,
                "hostname": hostname,
                "port": port,
                "is_https": is_https
            }
        },
        "summary": {
            "grade": grade,
            "owasp_compliance_score": owasp_score,
            "owasp_breakdown": breakdown,
            "total_findings": len(all_findings),
            "high_severity": high_count,
            "medium_severity": med_count,
            "low_severity": low_count,
            "headers_present_count": len(header_report.get("present_headers", [])),
            "headers_missing_count": len(header_report.get("missing_headers", [])),
            "ssl_valid": ssl_report.get("is_valid", False) if ssl_report else False
        },
        "ssl_tls": ssl_report,
        "headers": header_report,
        "findings": all_findings,
        "remediation_guide": {
            "nginx_snippet": generate_nginx_config(header_report.get("missing_headers", [])),
            "apache_snippet": generate_apache_config(header_report.get("missing_headers", [])),
            "express_snippet": generate_express_helmet_config()
        }
    }

    return audit_report


def generate_nginx_config(missing_headers: List[Dict[str, Any]]) -> str:
    """Generate ready-to-paste Nginx configuration directives."""
    lines = [
        "# Add inside your nginx server { ... } block:",
        "add_header X-Content-Type-Options \"nosniff\" always;",
        "add_header X-Frame-Options \"DENY\" always;",
        "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
        "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
        "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none';\" always;",
        "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=(), payment=()\" always;",
        "# Hide server version banner:",
        "server_tokens off;"
    ]
    return "\n".join(lines)


def generate_apache_config(missing_headers: List[Dict[str, Any]]) -> str:
    """Generate ready-to-paste Apache .htaccess / VirtualHost configuration directives."""
    lines = [
        "# Place inside <VirtualHost *:443> or .htaccess (requires mod_headers):",
        "<IfModule mod_headers.c>",
        "    Header always set X-Content-Type-Options \"nosniff\"",
        "    Header always set X-Frame-Options \"DENY\"",
        "    Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
        "    Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
        "    Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none';\"",
        "    Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"",
        "    Header unset X-Powered-By",
        "</IfModule>",
        "ServerSignature Off"
    ]
    return "\n".join(lines)


def generate_express_helmet_config() -> str:
    """Generate Node.js / Express snippet using helmet."""
    return """// npm install helmet
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
);
"""


def main():
    parser = argparse.ArgumentParser(
        description="Python Web Configuration & Header Security Analyzer (Passive & Defensive)"
    )
    parser.add_argument("url", nargs="?", help="Target URL or domain name to audit (e.g. https://example.com)")
    parser.add_argument("--json", action="store_true", help="Output audit report strictly as formatted JSON")
    parser.add_argument("--no-ssl", action="store_true", help="Skip SSL/TLS certificate verification step")
    parser.add_argument("--timeout", type=float, default=8.0, help="Socket and HTTP connection timeout in seconds (default: 8.0)")

    args = parser.parse_args()

    if not args.url:
        parser.print_help(sys.stderr)
        sys.exit(1)

    try:
        report = run_audit(args.url, check_ssl=(not args.no_ssl), timeout=args.timeout)
    except Exception as e:
        err_out = {"error": str(e), "url": args.url}
        if args.json:
            print(json.dumps(err_out, indent=2))
        else:
            print(f"Audit Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        meta = report["metadata"]["target"]
        summary = report["summary"]
        print("=" * 64)
        print(" PYTHON WEB CONFIGURATION & HEADER SECURITY ANALYZER")
        print("=" * 64)
        print(f"Target:       {meta['url']} ({meta['hostname']}:{meta['port']})")
        print(f"Timestamp:    {report['metadata']['timestamp']}")
        print(f"Grade:        {summary['grade']}  (OWASP Compliance Score: {summary['owasp_compliance_score']}/100)")
        print(f"Total Issues: {summary['total_findings']} (High: {summary['high_severity']}, Med: {summary['medium_severity']}, Low: {summary['low_severity']})")
        print("-" * 64)

        ssl_data = report.get("ssl_tls")
        if ssl_data and ssl_data.get("checked"):
            print("[SSL/TLS CERTIFICATE]")
            print(f"  Valid:          {ssl_data.get('is_valid')}")
            print(f"  TLS Version:    {ssl_data.get('tls_version')}")
            if ssl_data.get("days_remaining") is not None:
                print(f"  Days Remaining: {ssl_data.get('days_remaining')} days")
            if ssl_data.get("issuer"):
                print(f"  Issuer:         {ssl_data['issuer'].get('commonName') or ssl_data['issuer'].get('organizationName')}")
        elif ssl_data and not ssl_data.get("checked"):
            print(f"[SSL/TLS]: {ssl_data.get('reason')}")

        print("-" * 64)
        print(f"[SECURITY HEADERS] Present: {summary['headers_present_count']} | Missing: {summary['headers_missing_count']}")
        for m in report["headers"]["missing_headers"]:
            print(f"  [-] MISSING [{m['severity']}] {m['name']}")
        for p in report["headers"]["present_headers"]:
            status_tag = "[+]" if p["is_optimal"] else "[!]"
            print(f"  {status_tag} PRESENT {p['name']}")

        print("-" * 64)
        print("For full JSON audit report, re-run with --json flag.")
        print("=" * 64)


if __name__ == "__main__":
    main()
