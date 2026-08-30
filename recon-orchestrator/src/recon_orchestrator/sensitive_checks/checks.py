"""Sensitive checks: information disclosure and misconfiguration detection.

This module performs GET/HEAD requests on common sensitive paths and checks for
misconfigurations in HTTP headers and cookies. All activity is scoped to
authorized hosts and uses no payloads or injected parameters.
"""
from __future__ import annotations

import re
from typing import List, Set

import httpx

from ..config import Settings
from ..models import HostProbe

# Common sensitive paths that often leak information
_SENSITIVE_PATHS: List[str] = [
    "/.git/",
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.htaccess",
    "/.htpasswd",
    "/web.config",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/server-info",
    "/wp-config.php",
    "/configuration.php",
    "/config.php",
    "/admin/",
    "/administrator/",
    "/login.php",
    "/phpmyadmin/",
    "/test/",
    "/backup/",
    "/backups/",
    "/dump/",
    "/sql/",
    "/database.sql",
    "/backup.sql",
    "/robots.txt",  # While not sensitive itself, it reveals interesting paths
    "/.well-known/",
    "/.well-known/security.txt",
    "/.well-known/acme-challenge/",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
]

# Security headers that should be present for good security
_SECURITY_HEADERS: dict[str, str] = {
    "strict-transport-security": "HSTS should be enabled",
    "x-content-type-options": "Should be nosniff",
    "x-frame-options": "Should prevent clickjacking",
    "x-xss-protection": "Should enable XSS protection",
    "content-security-policy": "Should define CSP",
    "referrer-policy": "Should control referrer info",
    "permissions-policy": "Should limit browser features",
}

# Cookie flags that should be set for security
_SECURE_COOKIE_FLAGS: Set[str] = {
    "HttpOnly",
    "Secure",
    "SameSite",
}


async def check_sensitive_paths(
    host: str,
    settings: Settings,
    ports: List[int] | None = None,
) -> List[HostProbe]:
    """Check common sensitive paths on a host for information disclosure.

    Performs GET requests on common sensitive paths to discover information
    leakage. All requests are scoped to the target host and use only GET (no payloads).
    """
    if ports is None:
        # Check both HTTP and HTTPS on standard web ports
        ports = [80, 443]

    findings: List[HostProbe] = []

    for port in ports:
        scheme = "https" if port == 443 else "http"
        base_url = f"{scheme}://{host}:{port}"

        # Create a limited client for this check
        limits = httpx.Limits(
            max_connections=settings.max_concurrency,
            max_keepalive_connections=settings.max_concurrency,
        )
        timeout = httpx.Timeout(settings.http_timeout, connect=settings.connect_timeout)

        async with httpx.AsyncClient(
            headers={"User-Agent": settings.user_agent},
            timeout=timeout,
            limits=limits,
            verify=settings.verify_tls,
            follow_redirects=True,
        ) as client:
            for path in _SENSITIVE_PATHS:
                url = f"{base_url}{path}"
                try:
                    resp = await client.get(url)
                    # Only consider it a finding if we get a successful response
                    # (2xx, 3xx, or sometimes 401/403 which indicates the resource exists)
                    if resp.status_code < 500:  # Not a server error
                        headers = {k: v for k, v in resp.headers.items()}
                        # Extract title if HTML and small
                        title: str | None = None
                        if resp.text and len(resp.text) < 10000 and resp.headers.get("content-type", "").startswith("text/html"):
                            import re
                            match = re.search(r"<title[^>]*>([^<]+)</title>", resp.text, re.IGNORECASE)
                            if match:
                                title = match.group(1).strip()

                        findings.append(HostProbe(
                            host=host,
                            url=str(resp.url),
                            status=resp.status_code,
                            title=title,
                            server=headers.get("server") or headers.get("Server"),
                            port=port,
                            headers=headers,
                            fingerprints=[],  # We don't do full fingerprinting here
                        ))
                except (httpx.TransportError, httpx.HTTPError):
                    # Connection errors, timeouts, etc. - just skip this path
                    continue
                except Exception:
                    # Any other unexpected error - skip this path
                    continue

    return findings


def check_cors_misconfiguration(headers: dict[str, str]) -> List[str]:
    """Check for CORS misconfigurations in HTTP headers.

    Returns a list of descriptive strings about any misconfigurations found.
    """
    issues: List[str] = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    aco_header = headers_lower.get("access-control-allow-origin")
    if aco_header:
        if aco_header == "*":
            issues.append("CORS misconfiguration: Access-Control-Allow-Origin set to '*' (allows any origin)")
        elif aco_header.lower() == "null":
            issues.append("CORS misconfiguration: Access-Control-Allow-Origin set to 'null'")
        elif aco_header.startswith("http://") or aco_header.startswith("https://"):
            # Note: Specific origins are generally fine, so we don't flag those
            pass

    acac_header = headers_lower.get("access-control-allow-credentials")
    if acac_header and acac_header.lower() == "true":
        # If credentials are allowed, origin should not be wildcard
        if aco_header == "*":
            issues.append("CORS misconfiguration: Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: *")

    return issues


def check_security_headers(headers: dict[str, str]) -> List[str]:
    """Check for missing security headers in HTTP responses.

    Returns a list of descriptive strings about any missing recommended headers.
    """
    issues: List[str] = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header, description in _SECURITY_HEADERS.items():
        if header not in headers_lower:
            issues.append(f"Missing security header: {header} - {description}")

    return issues


def check_cookie_flags(headers: dict[str, str]) -> List[str]:
    """Check for missing secure flags in cookies.

    Returns a list of descriptive strings about any issues found.
    """
    issues: List[str] = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Handle potential multiple values for set-cookie header
    set_cookie_values = []
    for k, v in headers_lower.items():
        if k == "set-cookie":
            if isinstance(v, list):
                set_cookie_values.extend(v)
            else:
                set_cookie_values.append(str(v))

    for cookie_header in set_cookie_values:
        cookie_lower = cookie_header.lower()
        # Check if this cookie is missing important security flags
        missing_flags = []
        if "httponly" not in cookie_lower:
            missing_flags.append("HttpOnly")
        if "secure" not in cookie_lower:
            missing_flags.append("Secure")
        if "samesite" not in cookie_lower:
            missing_flags.append("SameSite")

        if missing_flags:
            # Extract cookie name for better reporting
            cookie_name = cookie_header.split("=")[0] if "=" in cookie_header else "unknown"
            issues.append(
                f"Cookie '{cookie_name}' missing security flags: {', '.join(missing_flags)}"
            )

    return issues


async def run_sensitive_checks(
    host: str,
    settings: Settings,
    ports: List[int] | None = None,
) -> List[HostProbe]:
    """Run all sensitive checks on a host and return findings as HostProbe objects.

    Combines path scanning with header/cookie analysis.
    """
    findings: List[HostProbe] = []

    # First, check sensitive paths
    path_findings = await check_sensitive_paths(host, settings, ports)
    findings.extend(path_findings)

    # For each successful probe from path scanning, also check headers and cookies
    # We'll do a quick HEAD request to get headers for header/cookie analysis
    if ports is None:
        ports = [80, 443]

    for port in ports:
        scheme = "https" if port == 443 else "http"
        base_url = f"{scheme}://{host}:{port}"

        limits = httpx.Limits(
            max_connections=settings.max_concurrency,
            max_keepalive_connections=settings.max_concurrency,
        )
        timeout = httpx.Timeout(settings.http_timeout, connect=settings.connect_timeout)

        async with httpx.AsyncClient(
            headers={"User-Agent": settings.user_agent},
            timeout=timeout,
            limits=limits,
            verify=settings.verify_tls,
            follow_redirects=True,
        ) as client:
            try:
                resp = await client.head(base_url)
                headers = {k: v for k, v in resp.headers.items()}

                # Check for issues and create informational probes
                cors_issues = check_cors_misconfiguration(headers)
                header_issues = check_security_headers(headers)
                cookie_issues = check_cookie_flags(headers)

                # Create a single probe that summarizes all header/cookie issues
                all_issues = cors_issues + header_issues + cookie_issues
                if all_issues:
                    findings.append(HostProbe(
                        host=host,
                        url=f"{base_url}/",
                        status=resp.status_code,
                        title="Security Headers/Cookies Analysis",
                        server=headers.get("server") or headers.get("Server"),
                        port=port,
                        headers=headers,
                        fingerprints=[],  # Not doing full fingerprinting here
                    ))
                    # In a real implementation, we might want to store the issues
                    # somewhere accessible, but for now we'll note they were found
            except (httpx.TransportError, httpx.HTTPError):
                # Connection problems - just skip header/cookie checks for this port
                pass
            except Exception:
                # Any other error - skip
                pass

    return findings