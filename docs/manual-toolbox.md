# Manual testing toolbox

A reference kit for the **human** active-testing step in this harness. The
autonomous runner only does passive recon on real programs and files leads to the
review queue; confirming a lead (XSS, IDOR, SSRF, SQLi, and so on) is your job, by
hand. This page collects the tools and commands for that manual phase.

Distilled and adapted from the public repo
[`DevCop95/bugbounty-lab101`](https://github.com/DevCop95/bugbounty-lab101) (MIT):
its 400-plus tool arsenal, 5-phase methodology, and payload notes. We keep the
reference and drop its autonomous-scanning posture.

---

## READ THIS FIRST (the safety line)

1. **Never point these at a real bug-bounty program automatically.** These are
   active tools (scanners, fuzzers, injection testers, exploit helpers). Running
   them against a real program can violate its rules (many forbid automated
   scanning or aggressive testing) and forfeit rewards. The harness stays passive
   on real programs on purpose. This toolbox does not change that.
2. **Only run active tools where you are explicitly authorized to** and where the
   program's policy allows the technique: your own systems, the practice targets
   (`vulnweb`, DVWA, Metasploitable), or a program that clearly permits it.
3. **Verify scope and the required header first** (`harness show-policy <p>`,
   golden rules in `AGENTS.md`). Asset-in-scope does not mean automation-allowed.
4. **One finding at a time, rate-limited, no destructive payloads.** You are
   confirming a specific lead, not blasting a target.

If a technique here conflicts with a program's policy, the policy wins. When in
doubt, stop and test only what is clearly allowed.

---

## The arsenal, by phase

Tool names as they appear in lab101's `tool-checker.sh`. Install what you use;
`tool-checker.sh` in that repo checks what is present.

| Phase | Tools |
|-------|-------|
| Recon / OSINT | `nmap` `masscan` `zmap` `dnsrecon` `theHarvester` `amass` `recon-ng` `whois` `dig` `host` `httpx` `katana` `gau` `nuclei` |
| Subdomains / DNS | `subfinder` `sublist3r` `fierce` `subbrute` `dnsgen` `gotator` `dnsenum` `dnsmap` |
| Web scan | `nikto` `whatweb` `gobuster` `dirb` `wfuzz` `ffuf` `feroxbuster` `dirsearch` `sqlmap` `xsser` `dalfox` `wpscan` `nuclei` |
| Content / params | `gobuster` `ffuf` `wfuzz` `feroxbuster` `dirsearch` `arjun` `paramspider` `x8` |
| Web exploitation | `sqlmap` `xsser` `dalfox` `xsstrike` `commix` `tplmap` `wpscan` `cmseek` |
| Enumeration | `enum4linux` `smbclient` |
| Brute force | `hydra` `medusa` `john` `hashcat` |
| Exploitation | `metasploit-framework` |
| Post-exploitation | `crackmapexec` `impacket-scripts` |

---

## 5-phase methodology (example commands)

Replace `target.com` with an asset you are authorized to actively test.

### 1. Reconnaissance
```bash
subfinder -d target.com -o subdomains.txt
amass enum -passive -d target.com >> subdomains.txt
httpx -l subdomains.txt -o live.txt
echo "target.com" | gau > wayback.txt
waybackurls target.com >> wayback.txt
katana -u "https://target.com" -d 3 -jc -o js_endpoints.txt
```

### 2. Scanning
```bash
echo "https://target.com" | nuclei -severity critical,high
nuclei -u "https://target.com" -t nuclei-templates/http/misconfiguration/cors*
dalfox url "https://target.com/?param=test"                 # XSS
sqlmap -u "https://target.com/?id=1" --batch --level=1       # SQLi
```

### 3. Fuzzing
```bash
feroxbuster -u "https://target.com" -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt
ffuf -u "https://target.com/FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
ffuf -u "https://target.com" -H "Host: FUZZ.target.com" -w subdomains.txt   # vhosts
```

### 4. Exploitation (by hand, careful)
```bash
# SSRF: try to reach cloud metadata
curl "https://target.com/api?url=http://169.254.169.254/latest/meta-data/"
# IDOR: increment/swap object ids   /user/123 -> /user/124
# Open redirect: test ?next= ?redirect= ?url= ?return=
```

### 5. Reporting
Bring the confirmed finding back into the harness: open the TUI (`harness`, press
`f`), add your verified evidence, run `harness dedup <program>` to check public
disclosures, preview the humanized report, and submit. Only you submit.

---

## Where the passive leads point you

The queue ranks leads (see `AGENTS.md` section 3). Map each to a manual test here:

| Lead from the queue | Manual confirm with |
|---------------------|---------------------|
| Auth boundary (401/403) on a sensitive path | access-control / IDOR by hand, session swaps |
| Reflected input signal | `dalfox`, `xsstrike`, manual XSS payloads |
| Version-disclosed service + CVE | targeted PoC for that CVE (see lab101 `docs/known-cve-watchlist.md`) |
| Exposed path (`.git`, `.env`, backup) | fetch and inspect by hand, confirm sensitivity |
| CORS `*` with credentials | manual cross-origin request, `nuclei` CORS templates |
| Subdomain takeover fingerprint | confirm the dangling CNAME and claim proof, no takeover |

## Vulnerability value tiers (lab101's rough guide)

- Critical (~$5,000+): RCE, SQLi with data access, auth bypass, SSRF to internal access, deserialization.
- High (~$1,000 to $5,000): stored XSS, IDOR to sensitive data, CSRF on critical actions, open redirect to account takeover.
- Medium (~$500 to $1,000): reflected XSS, CSRF on non-critical actions, info disclosure, missing rate limiting.

Reward depends on demonstrated impact, not the class alone. Lead your report with
impact, not severity labels.

## Further reference in lab101

- `docs/known-cve-watchlist.md`, `docs/known-cwe-watchlist.md`: CVE/CWE watchlists.
- `docs/hackerone-workflow.md`: the disclosure workflow.
- `bugbounty/QUICK-REFERENCE.md`: the source of the command snippets above.
