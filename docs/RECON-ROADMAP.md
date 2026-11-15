# Extending ReconForge with free open-source recon tools

ReconForge already integrates, with no API keys required: crt.sh
(Certificate Transparency), the Wayback Machine CDX API, Common Crawl,
RDAP, DNS records (dnspython), WHOIS, TCP-connect/HTTP/TLS probes and
Nmap (`-p-` TCP with service/OS detection, opt-in UDP).

This roadmap lists free and open-source tools that extend coverage
further, and where each one plugs into the architecture. Availability
and terms of free tiers change — verify each service's current terms
before relying on it, and keep every key in `settings.env` (never
committed).

## Where a new capability plugs in

| Extension point | Location | Pattern to follow |
|---|---|---|
| Passive connector | `reconforge/infrastructure/connectors/<name>.py` | `cert_transparency.py` — a `collect(target, client)` returning a JSON-serializable payload; register in `DiscoveryService._tasks` (discovery enrichment) and/or `OsintRunner` (stage 2), enable via `config/discovery.json` → `passive.<name>: true` |
| Active probe | `reconforge/infrastructure/probes/<name>.py` | `http_recon.py` / `tcp_recon.py` — invoked from `ActiveCheckRunner`, gated by scope policy, explicit asset approval and `--active` |
| Evidence analysis | `reconforge/domain/evidence_analysis.py` | pure functions over collected artifacts; render in `infrastructure/reporting/` |

Every connector must save its raw payload as evidence
(`save_evidence`) so provenance stays intact; every active tool must go
through the same authorization gates — no direct network access from
the domain or application layers.

## Passive OSINT (no target contact — safe by construction)

| Tool | What it adds | Integration point |
|---|---|---|
| **subfinder** | Fast passive subdomain enumeration across dozens of free passive sources | connector; map results to `subdomain` leads |
| **amass** (OWASP) | Broader subdomain + ASN/DNS-graph enumeration, DNS relationships | connector (passive mode) or periodic external run feeding the lead store |
| **assetfinder** | Lightweight passive subdomains — cheap first pass | connector |
| **dnsx** | Bulk DNS resolution, reverse DNS, wildcard/NX-domain detection | extend the `dns_recon` probe |
| **theHarvester** | Emails, hostnames, IPs from public search/archive sources | connector; feeds `email`/`subdomain` leads |
| **urlscan.io** | Public page scans: tech, IPs, requested URLs for a domain | connector (free API key) |
| **Shodan** (free account) | Internet-wide view of approved IPs: banners, open ports as seen externally | connector keyed by approved IPs only |
| **Censys** (free tier) | Independent host/service/certificate metadata | connector keyed by approved IPs/domains |
| **VirusTotal** (free API key) | Passive DNS, resolutions, relations | connector |
| **SecurityTrails** (free tier) | Historical DNS, subdomain records | connector |
| **SpiderFoot** | 150+ modular OSINT sources orchestrated externally | run externally; import its output as leads |

## Archives, code and secrets exposure

| Tool | What it adds | Integration point |
|---|---|---|
| **gau** / **waybackurls** | Bulk archived + linked URLs beyond the CDX record limit | extend the `wayback` connector's URL harvesting |
| **trufflehog** / **gitleaks** | Secrets/credentials in public repositories | connector on the `github` source; findings stay observations until validated |
| **GitHub code search** (free, authenticated) | Domain/token mentions in public code | deepen the existing `github` connector |

## Active technical extension (authorized scope only)

| Tool | What it adds | Integration point |
|---|---|---|
| **naabu** / **masscan** / **zmap** | High-speed full-range port pre-scans on large CIDRs; feed confirmed-open ports to Nmap `-sV` for detail | probe executed per approved asset, before the Nmap inventory |
| **httpx** | Mass HTTP probing: live confirmation, titles, tech, status codes | probe complementing `http_recon` |
| **whatweb** / **Wappalyzer** | Web technology fingerprinting | probe; store fingerprints as observations |
| **nuclei** | Template-driven checks (~thousands of community templates) | probe; output enters `assessment.findings` only via reviewer validation |
| **nikto** | Web-server misconfiguration checks | probe on approved HTTP assets |
| **testssl.sh** / **sslscan** / **sslyze** | TLS protocol/cipher analysis, certificate weaknesses | extend the `tls` probe |
| **ffuf** / **gobuster** / **feroxbuster** | Directory and virtual-host content discovery | probe with a wordlist parameter |
| **katana** / **hakrawler** | JS-aware crawling for endpoints and parameters | probe; endpoints become evidence for analysis |
| **wafw00f** | WAF detection in front of approved assets | probe; influences interpretation of blocking behavior |
| **dnsrecon** / **fierce** | Zone enumeration, reverse lookups, subdomain brute force | probe (active DNS) |
| **Nmap NSE scripts** | Targeted `http-*`, `ssl-*`, `smb-*` script checks | extend `_scan_command` with an optional script list in config |

## Cloud-target extensions (`mode=cloud`)

| Tool | What it adds |
|---|---|
| **cloud_enum** | Public enumeration of AWS/Azure/GCP assets from names |
| **S3Scanner** | Open-bucket detection for explicitly authorized bucket names |
| **GrayHat Warfare** (limited free) | Public bucket search by keyword |

## Suggested adoption order

1. **subfinder + amass (passive)** — biggest breadth gain, zero target
   contact, feeds the existing lead/correlation pipeline immediately.
2. **httpx** — confirms which discovered hosts are live before active
   authorization is even requested.
3. **testssl.sh / sslscan** — TLS configuration depth beyond the
   current single-certificate probe.
4. **nuclei** — systematic technical checks, but keep the reviewer
   gate: template hits enter the report as observations first.
5. **naabu or masscan** — only if large authorized CIDRs make Nmap's
   full-range sweep the bottleneck.
6. **Shodan/Censys** — external corroboration for approved IPs.

## Ground rules for every addition

- **Scope first:** leads and targets flow through
  `config/scope.json` + exclusions; active tools only ever touch
  explicitly approved assets.
- **Evidence provenance:** raw tool output is saved as evidence JSON;
  normalized results reference that path.
- **No silent severity:** tool output is classified as observation;
  vulnerability status is assigned in the reviewer-controlled report
  step, never automatically.
- **Rate limits and keys:** respect each source's limits
  (`limits.requests_per_minute` pattern), store keys in
  `settings.env`.
