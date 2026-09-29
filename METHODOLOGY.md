# Methodology: understanding the bug bounty machine

This document explains how each module in the security-harness maps to
real-world bug classes and vulnerability types, so it is clear what each part
looks for and why, rather than scanning blindly.

## Core principles

1. **Mode-gated aggression**: A program's mode decides how far the machine goes
   on its own. `real` targets (live bug-bounty programs) are passive: GET/HEAD
   only, no payloads, no exploitation. `practice` targets (intentionally
   vulnerable sites you own or are meant to exploit) arm the active engine. The
   default is passive, and a real program is forced passive on every autonomous
   run.
2. **Scope-gated operations**: Every check respects authorized boundaries via
   ScopeGuard.
3. **Candidate generation**: Outputs are leads for manual verification, not
   vulnerability claims.
4. **Chaining for context**: Modules build on each other to create a richer
   picture of the attack surface.

---

## Module 0: Nightly orchestrator
**Bug class**: Forgotten / abandoned assets  
**Why it matters**: Many breaches start with assets that organizations forgot they owned (dev.staging.company.com, old acquisitions, shadow IT). The nightly runner continuously scans authorized programs to catch:
- Newly exposed subdomains
- Forgotten test/dev environments
- Assets that drifted into scope due to misconfiguration
- Changes in third-party services that introduce risk

**Real-world equivalent**: Continuous asset inventory and change detection, the foundation of attack surface management.

---

## Module 1: Passive subdomain enumeration (crt.sh)
**Bug class**: Forgotten assets / inventory gaps  
**Why it matters**: Certificate Transparency logs reveal subdomains organizations didn't know were issued, often for:
- Development/staging environments mistakenly issued public certs
- Forgotten marketing sites or campaign microsites
- Acquired companies' domains not yet integrated
- Internal systems accidentally exposed via public certs

**Real-world equivalent**: Discovering assets through third-party passive sources, which is how attackers find your blind spots.

---

## Module 2: Port sweep + tech stack detection
**Bug class**: Exposure of legacy / unpatched services  
**Why it matters**: Finding non-standard ports and fingerprinting technology reveals:
- Forgotten services running on unusual ports (management interfaces, databases, admin panels)
- Legacy systems that missed patch cycles
- Development tools exposed to internet (git, docker registries, k8s dashboards)
- Misconfigured services that should be internal-only

**Real-world equivalent**: Network reconnaissance that finds the nooks and crannies where attackers gain initial footholds.

---

## Module 3: CPE-based CVE correlation
**Bug class**: Known vulnerabilities in exposed services  
**Why it matters**: Moving from string matching to CPE (Common Platform Enumeration) correlation provides:
- Accurate version-specific CVE mapping (nginx/1.18.0 ≠ nginx/1.20.0)
- Reduction in false positives from generic product matches
- Focus on exploitable versions where patches exist
- Alignment with how vulnerability scanners and threat intel operate

**Real-world equivalent**: Vulnerability management, finding known bugs in exposed services before attackers do.

---

## Module 4: Sensitive path + header/cookie checks
**Bug class**: Information disclosure and misconfiguration  
**Why it matters**: These checks find low-hanging fruit that often leads to chain exploits:
- **Sensitive paths**: .git/HEAD (source leakage), .env (secrets), phpinfo.php (debug info)
- **CORS misconfigurations**: Access-Control-Allow-Origin: * with credentials (account takeover)
- **Missing security headers**: No CSP, no HSTS (increases exploit impact)
- **Insecure cookies**: Missing HttpOnly/Secure/SameSite (session theft, CSRF)

**Real-world equivalent**: Configuration auditing, finding the mistakes that turn theoretical vulns into breaches.

---

## Module 5: HackerOne scope import
**Bug class**: Scope drift and misunderstanding  
**Why it matters**: Many programs fail not from lack of skill, but from scanning the wrong targets:
- Accidentally testing out-of-scope assets (legal risk, wasted effort)
- Missing newly added scope (reduced coverage)
- Misunderstanding wildcard rules (accidental over-scoping or under-scoping)
- Not respecting program-specific restrictions (bounty eligibility)

**Real-world equivalent**: Scope discipline, the boundary that separates ethical hunting from unauthorized access.

---

## Module 6: Triage dashboard / morning queue
**Bug class**: Prioritization failure  
**Why it matters**: Not all findings are equal, so the triage system focuses human attention where it matters most:
- **Non-prod naming** (dev, staging, test): Weaker controls, debug surfaces
- **Admin/internal tooling** (jenkins, grafana, jira): High-value targets often mis-scoped
- **Auth boundaries** (401/403): Worth probing access control flaws
- **Server errors** (500+): Possible error leakage and information disclosure
- **Non-standard ports**: Forgotten services? (often legacy/unpatched)
- **Default titles**: Unfinished/forgotten deployments
- **Version disclosure**: CVE surface for known vulns

**Real-world equivalent**: Risk-based prioritization, focusing limited human effort on the most promising leads.

---

## How the modules chain together

The value comes from combining modules to build a coherent picture:

1. **Discovery** (Modules 0-2): What assets exist and what technologies they run
2. **Vulnerability correlation** (Module 3): What known bugs affect those technologies
3. **Misconfiguration scan** (Module 4): What mistakes were made in deployment/configuration
4. **Scope validation** (Module 5): Are we looking at the right things?
5. **Prioritization** (Module 6): Where should humans focus their manual testing?

This mirrors professional penetration testing methodology (reconnaissance,
vulnerability identification, exploitation attempt, reporting) but with ethical
boundaries: against **real** programs it stops at candidate generation and
requires manual verification; autonomous **exploitation** runs only against
**practice** targets that exist to be attacked. A human always verifies and
submits.

---

## Expected output types

Each module produces specific, actionable findings:

- **Subdomain enumeration**: List of discovered hosts (for further scanning)
- **Port/tech detection**: Service fingerprints with versions (for CVE correlation)
- **CVE matches**: CVE IDs with CVSS scores and explanations (for research)
- **Sensitive paths**: URLs that returned interesting responses (for manual inspection)
- **Header/cookie issues**: Specific misconfiguration descriptions (for fixing)
- **Triage score**: Ranked list with signals explaining why each target interests us

---

## Manual verification process

The machine's output is only the beginning. For each candidate lead:

1. **Confirm scope**: Double-check that the target is authorized
2. **Manual inspection**: Visit sensitive paths, check headers, test CORS properly
3. **Version verification**: Confirm the actual version matches the fingerprint
4. **Exploit research**: Look up public exploits for matched CVEs
5. **Chaining**: Combine findings (e.g., subdomain takeover + sensitive Git repo)
6. **Document**: Clear steps to reproduce, impact assessment
7. **Report**: Follow the program's template, include all required details

---

## Why this approach holds up

It never crosses into unauthorized testing or exploitation against real
programs, it focuses human effort on the highest-yield targets, and it can run
continuously without generating noise or legal risk.

This is how you build a sustainable bug-bounty pipeline: automate the mechanical
work (discovery, prioritization, and report drafting) and reserve human
judgement for what is real, what pays, and what is legal to do. Against **real**
programs the machine never exploits or submits on its own; it surfaces leads,
and a human verifies and submits each one from the TUI. Autonomous
**exploitation** is confined to **practice** targets that exist to be attacked.
That split is what keeps the pipeline both effective and inside the rules.

---

*Built for the security-harness framework. Each module is scope-gated and
passive by default.*
