# ReconForge

ReconForge is a modular framework for **authorized external reconnaissance, passive OSINT, controlled technical discovery, evidence analysis, and reviewer-led security assessment**. It is designed for educational cybersecurity work and authorized security assessments.

The project combines public intelligence sources with low-impact technical checks. It keeps scope enforcement, evidence provenance, scan limitations, and human review explicit. ReconForge is not an exploitation framework and does not treat an exposed service, a search result, or an intelligence lead as a confirmed vulnerability.

## Architecture (v0.8.0 — clean architecture)

The package is layered with the dependencies pointing strictly inward:

```text
reconforge/
├── interfaces/cli/        # Delivery: argparse commands, console, composition root
├── application/           # Use cases (one small class per command), services, ports
│   ├── use_cases/         #   InitializeWorkspace, ValidateTarget, RegisterEngagement,
│   │                      #   ListEngagements, CollectPassiveOsint, CorrelateIntelligence,
│   │                      #   DiscoverAssets, AnalyzeEvidence, AssembleAssessment,
│   │                      #   RunEngagementPipeline (one-command end-to-end run)
│   ├── services/          #   correlation, asset inventory, discovery orchestration
│   ├── ports.py           #   Protocols: repositories, artifact store, renderers, console
│   └── workspace.py       #   WorkspaceLayout / EngagementLayout value objects
├── domain/                # Pure business logic — no I/O, no framework imports
│   ├── scope.py           #   target validation (Validation value object)
│   ├── scope_policy.py    #   scope policy matching, exclusions
│   ├── leads.py           #   LeadSpec + connector lead extraction
│   ├── prioritization.py  #   lead group scoring
│   ├── triage.py          #   standalone lead triage API
│   ├── exposure_rules.py  #   ExposureRule + port-based assessment
│   ├── evidence_analysis.py  # Nmap/TCP/HTTP evidence classification
│   ├── assessment.py      #   final assessment assembly, review worksheet
│   └── pipeline.py        #   PipelineStep: the readable step vocabulary
├── shared/                # paths, clock, dict helpers (cross-layer, pure)
└── infrastructure/        # Adapters implementing the ports
    ├── persistence/       #   SQLite repositories, evidence store, provenance reader
    ├── connectors/        #   passive OSINT connectors + runner
    ├── probes/            #   DNS, HTTP/TLS, TCP, Nmap technical checks
    ├── reporting/         #   Markdown/PDF renderers per step
    └── http/              #   rate-limited, caching HTTP client
```

Two rules are enforced by a regression test: `domain/` and
`application/use_cases/` never import `infrastructure/` or `interfaces/`;
application services may compose infrastructure adapters directly.

## Capability snapshot

The current source tree contains:

- **10 passive OSINT connector adapters** under `reconforge/infrastructure/connectors/` (including one social-platform adapter registry that is intentionally not implemented).
- **4 technical-reconnaissance probe modules** under `reconforge/infrastructure/probes/`.
- **6 named workflow steps**, from engagement registration through reviewer-led assessment: `register` → `passive` → `intel` → `discover` → `analyze` → `report`. The `run` command executes the whole workflow in one invocation.
- Local evidence storage, correlation, prioritization, Markdown/PDF reporting, and automated tests.

These are module counts, not a claim that ReconForge invokes independent third-party scanning programs. Most connectors query public web services; technical checks use Python networking, `dig`, and Nmap where configured.

## Implemented integrations and sources

### Passive OSINT connectors — `reconforge/infrastructure/connectors/`

| Module | Source / integration | Current role and status |
|---|---|---|
| `dns_whois.py` | `dig`, `whois` | DNS records and WHOIS lookups; requires the corresponding system utilities |
| `cert_transparency.py` | crt.sh | Certificate Transparency records and hostname discovery |
| `rdap.py` | RDAP (`rdap.org`) | Domain registration events, nameservers, status and entity metadata |
| `archive.py` | Internet Archive CDX | Historical URLs and archived publication metadata |
| `wayback.py` | Internet Archive Wayback Machine CDX | Root-domain and subdomain historical URL discovery; wired into Discovery |
| `commoncrawl.py` | Common Crawl Index | Historical crawl index records; wired into Discovery |
| `github.py` | GitHub public REST API | Public repository search; optional `GITHUB_TOKEN` improves API access limits |
| `wikipedia.py` | Wikipedia MediaWiki API | Contextual public reference search |
| `search_provider.py` | Brave Search API / configured search provider | Optional search enrichment; requires provider configuration and API credentials |
| `social_sources.py` | LinkedIn, X and Facebook registry | **Adapter-only**. No scraping or login automation; calls currently raise `NotImplementedError` until an approved API or permitted source is configured |

The passive runner wires DNS, WHOIS, crt.sh, Internet Archive (`archive.py`), GitHub, Wikipedia and optional configured search. Discovery separately wires wayback, crt.sh, RDAP, Common Crawl and DNS record collection. The presence of a connector file does not mean every step invokes it.

### Technical reconnaissance probes — `reconforge/infrastructure/probes/`

| Module | Function | Execution conditions |
|---|---|---|
| `dns_recon.py` | Collects A, AAAA, CNAME, MX, NS, TXT, CAA and SOA DNS answers using `dig` | Used by Discovery passive enrichment |
| `http_recon.py` | HTTP metadata and TLS certificate inspection | Active mode and exact approved hostname required |
| `tcp_recon.py` | TCP connection checks against selected ports | Active mode plus explicit authorization of the resolved IP under scope policy |
| `nmap_recon.py` | Nmap port discovery, service/version identification and OS fingerprint matching | Requires active mode, Nmap configuration, explicit asset approval and explicit IP/CIDR scope authorization |

Nmap preserves native `.nmap`, `.gnmap`, and `.xml` output. TCP scanning is not automatically authorized by domain ownership or hostname approval. ReconForge checks resolved IP addresses against the explicit IP/CIDR scope policy; exclusions override allow rules.

### Internal and cloud reconnaissance — not yet implemented

`reconforge/infrastructure/connectors/internal/` and `.../cloud/` currently contain package placeholders only. Engagement modes can represent `internal`, `cloud`, and `hybrid`, but the current source tree does **not** yet provide operational internal-network discovery, Active Directory enumeration, AWS/Azure/GCP inventory, cloud posture assessment, or cloud API integrations. These capabilities must not be represented as completed features until their modules, authorization controls, evidence handling, and tests are implemented.

## Pipeline

```text
Engagement registration and scope validation
                  |
                  v
       passive — Passive OSINT
  DNS / WHOIS / CT / RDAP / archives /
  Common Crawl / GitHub / Wikipedia / search
                  |
                  v
         intel — Correlation and prioritization
 Normalize -> correlate -> score -> leads
                  |
                  v
       discover — Controlled technical discovery
 Asset inventory + DNS + HTTP/TLS + TCP + Nmap
                  |
                  v
        analyze — Evidence analysis
 Consolidate observations, gaps and provenance
                  |
                  v
     report — Reviewer-led assessment
 Validate candidates -> findings -> reports
```

### Project layout

```text
ReconForge/
├── recon.py              # Single CLI entry point (every command)
├── reconforge/           # The layered application package (see Architecture)
├── config/               # Local settings, scope and Discovery examples
├── docs/                 # RECON-ROADMAP.md — extending recon with free OSS tools
├── tests/                # Unit, regression and architecture tests
├── output/               # Engagement evidence and generated reports
├── logs/                 # Application logs
├── conftest.py           # Test import bootstrap (pytest/unittest)
├── pyproject.toml        # Packaging metadata and tool configuration
├── REFACTORING.md        # Change log of the refactoring passes
└── requirements.txt
```

## Installation

On Kali/Debian-based systems:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip dnsutils whois nmap

cd ~/ReconForge
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

cp config/settings.env.example config/settings.env
chmod 600 config/settings.env

python3 recon.py init
```

Edit configuration files with Vim, for example:

```bash
vim config/settings.env
vim config/scope.json
vim config/discovery.json
```

Keep credentials in local environment configuration. Do not commit `settings.env`, API tokens, private evidence, or engagement-specific authorization material.

## Workflow and commands

The project has a single entry point: `recon.py`. Every workflow command — engagement setup, passive collection and the four pipeline steps — is a subcommand of it:

```bash
python3 recon.py <command> [options]
python3 recon.py --help
```

After `pip install .` the same interface is available as the `recon` console script (`recon discover --engagement 1`).

### One-command workflow

`run` executes the whole engagement workflow end to end. Without `--engagement` it registers a new engagement first; with `--engagement` it reuses an existing one. It then runs passive collection, intel, discovery, analysis and the reviewer-led report, stopping at the first failing step (passive connector errors are reported but do not stop the run):

```bash
# Everything for a new engagement, from registration to the final report:
python3 recon.py run \
  --target example.org \
  --type domain \
  --mode external \
  --authorization "AUTH-REFERENCE" \
  --owner "Engagement Owner"

# Or rerun the whole workflow for an already-registered engagement:
python3 recon.py run --engagement 1

# Include authorized active checks / Nmap in the run (same gates as discover):
python3 recon.py run --engagement 1 --active --nmap

# Probe a URL across every IP it resolves to, all ports, one command:
python3 recon.py run --engagement 1 --active --nmap --all-ports --probe-resolved
```

Useful options: `--sources` (passive connector set), `--search-query`, `--config` (discovery config; falls back to `config/discovery.json`, then to the shipped passive-only `config/discovery.json.example`), `--database`, `--output-root`, `--reviewer`. The command exits `0` when all steps succeed and `2` when a step fails, printing which step stopped the run.

### Probing every IP a URL (or domain) resolves to

Register the engagement with `--type url` (e.g. `https://app.example.org/login`) or use a `domain` target, then add `--probe-resolved` to `discover`/`run` together with `--active`:

```bash
python3 recon.py register --target "https://app.example.org/login" \
  --type url --mode external --authorization "AUTH-REFERENCE" --owner "Owner"

# Passive collection records a url_resolution evidence file; active probing
# covers the URL's hostname, HTTP/TLS, and every resolved address:
python3 recon.py discover --engagement 2 --active --nmap --all-ports --probe-resolved
```

How authorization works for this flow: the engagement target itself is the basis — its hostname is added to the checked assets and every address it resolves to (A/AAAA) is approved for TCP/Nmap probing **for this run only**. Explicit exclusions (`config/exclusions.txt` and the policy's `exclude` section) still override; the scope policy, `active.enabled`/`nmap.enabled` config gates and `--active` are still required. The discovery artifact records `resolved_target_ips` with each address and its disposition (approved / excluded / unresolved) for provenance.

### 1. Initialize and validate an engagement

```bash
python3 recon.py init

python3 recon.py validate \
  --target example.org \
  --type domain \
  --mode external
```

Register only after obtaining authorization. Use the authorization reference and owner required by your engagement process:

```bash
python3 recon.py register \
  --target example.org \
  --type domain \
  --mode external \
  --authorization "AUTH-REFERENCE" \
  --owner "Engagement Owner"

python3 recon.py engagements
```

Record the engagement ID returned by registration and use it in subsequent steps.

### 2. Normal / passive workflow

The passive workflow does not enable Discovery active HTTP/TLS, TCP, or Nmap checks.

```bash
# Passive: run the default passive source set
python3 recon.py passive --engagement 1

# Or choose sources explicitly
python3 recon.py passive \
  --engagement 1 \
  --sources dns,whois,crtsh,archive,github,wikipedia

# Optional search enrichment (requires configured provider credentials)
python3 recon.py passive \
  --engagement 1 \
  --sources dns,whois,crtsh,archive,github,wikipedia,search \
  --search-query '"example.org"'

# Intel: correlate and prioritize collected intelligence
python3 recon.py intel --engagement 1

# Discovery: passive enrichment only (no --active and no --nmap)
python3 recon.py discover --engagement 1

# Analyze: local evidence analysis
python3 recon.py analyze --engagement 1

# Report: final reviewer-controlled assessment
python3 recon.py report --engagement 1
```

### 3. Authorized active workflow

Active checks are opt-in and require an engagement with documented authorization. First inspect and edit the scope and Discovery configuration:

```bash
cp config/discovery.json.example config/discovery.json
chmod 600 config/discovery.json
vim config/discovery.json
vim config/scope.json
```

For the intended targets:

1. Set `active.enabled` to `true`.
2. Add exact approved hostnames/assets to `active.approved_assets`.
3. Set `nmap.enabled` to `true` only when Nmap is authorized.
4. Add each explicitly authorized resolved IP address or CIDR to `config/scope.json` under `allow.ips` or `allow.cidrs`.
5. Keep exclusions in the `exclude` policy. Exclusions override allow rules.
6. Enable UDP only when it has been separately authorized. UDP is disabled by default; the configured default top-port set is 1,000. Full UDP range scanning requires a separate explicit decision.

**Important authorization boundary:** approving a domain or hostname does not automatically authorize scanning every IP address returned by DNS. HTTP/TLS hostname checks and IP-level TCP/Nmap checks have distinct authorization gates. ReconForge filters resolved addresses through the explicit IP/CIDR scope policy and does not scan unapproved addresses.

Run the approved checks:

```bash
# HTTP/TLS, TCP-connect and Nmap checks
python3 recon.py discover --engagement 1 --active --nmap

# Same, sweeping every port: TCP 1-65535 (Nmap always does this) plus
# all UDP ports instead of the UDP top-1,000 default
python3 recon.py discover --engagement 1 --active --nmap --all-ports

# Then analyze and report locally
python3 recon.py analyze --engagement 1
python3 recon.py report --engagement 1
```

`--nmap` requires `--active`, `nmap.enabled=true`, `active.enabled=true`, explicit asset approval, and a successful scope-policy check. Nmap may need elevated privileges for OS fingerprinting; without raw-socket privileges, some fingerprinting may be unavailable or Nmap may use connect scanning.

### Full port coverage

Port coverage has two halves:

- **TCP — full range by design.** Every authorized Nmap run scans all 65,535 TCP ports (`-p-`) with service detection and OS fingerprinting; there is no "top ports" shortcut in the TCP inventory.
- **UDP — opt-in and configurable.** Disabled by default. When enabled, it sweeps the configured top-N ports (default 1,000). Pass `--all-ports` (to `discover` or `run`) to sweep the entire UDP range instead — expect long runtimes; the per-host timeout (`nmap.host_timeout`, default `20m` TCP / `30m` UDP) bounds each approved asset.

```bash
# Everything at once — passive collection, gated active checks, full TCP
# range and the full UDP range, ending in the reviewer-ready report:
python3 recon.py run --engagement 1 --active --nmap --all-ports
```

For large networks, stage the work: enumerate in-scope assets first (`discover` passive-only), approve the specific IPs you are authorized to touch in `config/scope.json`, then run the full sweep per approved asset. A fast external pre-scanner (see `docs/RECON-ROADMAP.md`) can shorten full-range sweeps on big CIDR blocks, but ReconForge itself only scans addresses the scope policy explicitly allows.

### Discovery output

```text
output/engagement-<ID>/discover/
├── discover.json
├── discover-report.md
├── discover-report.pdf
└── nmap/
    ├── <asset>-<approved-IP>-<timestamp>-<index>-tcp.nmap
    ├── <asset>-<approved-IP>-<timestamp>-<index>-tcp.gnmap
    ├── <asset>-<approved-IP>-<timestamp>-<index>-tcp.xml
    └── <asset>-<approved-IP>-<timestamp>-<index>-udp.*  # if enabled
```

The structured JSON and native Nmap files are the machine-readable evidence. Nmap does not necessarily emit one XML row for every closed port; aggregate `extraports` counts are retained instead of inventing per-port records. Scan errors, timeouts, routing failures and incomplete coverage must remain visible in interpretation and reporting.

## Analyze — Evidence analysis

The `analyze` step is local-only. It consolidates intel and discovery artifacts, records provenance and evidence gaps, and distinguishes completed, partial, skipped and failed collection. It does not initiate new network requests or promote an observation into a confirmed vulnerability merely because a port is reachable or a response header is absent.

Section 8 of the analysis report (`analyze/analyze-report.md`) is an **Evidence Source Coverage** matrix: every passive connector, intel source and active probe is listed with its observation count and status, so the report's breadth is visible at a glance — Nmap is one row among many, and failed sources are marked as errors rather than silently dropped.

```bash
python3 recon.py analyze --engagement 1
```

## Report — Final assessment and reviewer-controlled reporting

The report step consolidates engagement records, intel, discovery and analysis artifacts. It is local-only: it does not scan, exploit, or make new network requests.

```bash
python3 recon.py report --engagement 1
```

Optional arguments:

```bash
python3 recon.py report \
  --engagement 1 \
  --database output/reconforge.sqlite3 \
  --output-root output \
  --reviewer "Assessment Reviewer"
```

Outputs:

```text
output/engagement-<ID>/report/
├── assessment.json
├── review-worksheet.json
├── assessment.md
└── assessment.pdf
```

### Manual review and vulnerability classification

The first run creates `review-worksheet.json` with pending candidates from provisional Discovery findings and selected analysis observations. Review the worksheet with Vim:

```bash
vim output/engagement-1/report/review-worksheet.json
```

Set each candidate's `review_status` to `accepted`, `rejected`, or `deferred`, and provide a reviewer classification. A candidate may be published as a `confirmed_vulnerability` only after reviewer acceptance and completion of the required evidence, rationale, demonstrated impact, severity, and remediation fields.

Identifier and severity highlighting in the reports:

- Discovery findings arrive with a **rule-mapped CWE** and a severity; both are highlighted (severity roll-up plus bold per-finding severity) in the analysis report and carried into the review worksheet as suggestions to validate.
- A confirmed finding is published with its **CVE**, **CWE** and a **CVSS v3.1 block (score, severity, vector, source)** shown prominently — bold severity in Markdown, colored severity badges in the PDF, and a severity roll-up at the top of the findings sections.
- You supply only the **CVSS vector**; ReconForge computes the score and severity band from it using the FIRST CVSS v3.1 specification formula (spec section 8.2). A manually supplied score that disagrees with the vector is flagged as a validation issue.

For confirmed vulnerability reporting:

- Include a **CWE** only when the weakness classification is supported by evidence.
- Include a **CVE** only when an applicable vulnerability identifier has been independently validated. A product/version banner alone is not sufficient.
- Include a complete and valid **CVSS v3.1 vector** when the finding has enough technical evidence for defensible scoring. Do not derive CVSS from port exposure alone.
- If no applicable CVE exists or one cannot be substantiated, state that clearly rather than inventing an identifier.

Intel leads remain intelligence. TCP reachability, missing headers, banners and provisional exposure recommendations remain observations unless independently validated. Incomplete Nmap coverage and evidence gaps must remain visible in the final report. Existing reviewer decisions are preserved when the review worksheet is regenerated; new candidates are appended.

## Extending reconnaissance with free open-source tools

`docs/RECON-ROADMAP.md` maps the free OSS ecosystem onto this codebase:
passive subdomain/OSINT sources (subfinder, amass, theHarvester,
urlscan.io, Shodan/Censys free tiers), archive and secrets exposure
(gau, TruffleHog, gitleaks), active technical depth (httpx, whatweb,
nuclei, testssl.sh, naabu/masscan, NSE scripts) and cloud enumeration —
each with its exact integration point (passive connector, active probe,
or analysis extension), the evidence-provenance rules every addition
must follow, and a suggested adoption order.

## Interpretation and safety principles

- ReconForge is for authorized assets and documented assessment scope only.
- Passive discovery does not grant permission for active testing.
- Domain/hostname approval does not implicitly authorize resolved IP addresses for TCP/Nmap scans.
- Exclusions override allow rules.
- Nmap service/version results and CPEs are leads for manual vendor-advisory/CVE validation, not proof of exploitability.
- The framework does not run Nmap NSE vulnerability scripts or exploitation checks.
- An exposed RDP, Telnet, SMB, database, Redis, VNC or Docker API listener warrants review but does not by itself prove weak authentication, data access or a vulnerability.
- Historical URLs are not confirmed live endpoints; do not automatically request archived paths.
- A lack of findings is not proof that an asset is vulnerability-free, especially when collection is partial or a source was unavailable.

## Testing

Run the complete test suite from the project root with the virtual environment active:

```bash
python3 -m unittest discover -s tests -v
```

Or with pytest:

```bash
python3 -m pytest
```

Lint the codebase (configuration lives in `pyproject.toml`):

```bash
python3 -m ruff check reconforge tests
```

Focused test runs:

```bash
python3 -m unittest tests.test_discovery_scope -v
python3 -m unittest tests.test_discovery_nmap_gate -v
python3 -m unittest tests.test_analysis -v
python3 -m unittest tests.test_assessment -v
```

## Current implementation status

| Capability | Status |
|---|---|
| Engagement registration, validation and local persistence | Implemented |
| Passive OSINT collection and evidence storage | Implemented; provider availability and credentials vary |
| Correlation, normalization and prioritization | Implemented |
| Passive discovery asset inventory | Implemented |
| Active HTTP/TLS and TCP checks | Implemented behind explicit approval and scope gates |
| Nmap TCP scanning and optional separately authorized UDP | Implemented behind explicit approval and scope gates |
| Local evidence analysis | Implemented |
| Reviewer-controlled assessment and Markdown/PDF reporting | Implemented |
| Internal network / Active Directory reconnaissance | Not implemented; placeholder package only |
| Cloud reconnaissance / cloud posture integrations | Not implemented; placeholder package only |
| LinkedIn, X and Facebook collection | Adapter-only; not implemented |

## Responsible use

Use ReconForge only against systems for which you have explicit authorization. Follow the engagement rules of engagement, minimize operational impact, protect collected evidence, and retain an auditable record of scope, configuration, commands, outputs, limitations and reviewer decisions.
