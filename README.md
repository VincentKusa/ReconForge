# ReconForge

ReconForge is a modular framework for **authorized external reconnaissance, passive OSINT, controlled technical discovery, evidence analysis, and reviewer-led security assessment**. It is designed for educational cybersecurity work and authorized security assessments.

The project combines public intelligence sources with low-impact technical checks. It keeps scope enforcement, evidence provenance, scan limitations, and human review explicit. ReconForge is not an exploitation framework and does not treat an exposed service, a search result, or an intelligence lead as a confirmed vulnerability.

## Architecture (v0.8.0 — clean architecture)

The package is layered with the dependencies pointing strictly inward:

    reconforge/
    ├── interfaces/cli/        # Delivery: argparse commands, console, composition root
    ├── application/           # Use cases (one small class per command), services, ports
    │   ├── use_cases/         #   InitializeWorkspace, ValidateTarget, RegisterEngagement,
    │   │                      #   ListEngagements, CollectPassiveOsint, CorrelateIntelligence,
    │   │                      #   DiscoverAssets, AnalyzeEvidence, AssembleAssessment,
    │   │                      #   RunEngagementPipeline (one-command end-to-end run)
    │   ├── services/          #   correlation, asset inventory, discovery orchestration,
    │   │                      #   cve_lookup (NVD candidate enrichment),
    │   │                      #   nmap_fingerprint (Nmap XML -> domain fingerprints)
    │   ├── ports.py           #   Protocols: repositories, artifact store, renderers, console,
    │   │                      #   web fingerprint, WAF, CVE lookup, Nmap XML
    │   └── workspace.py       #   WorkspaceLayout / EngagementLayout value objects
    ├── domain/                # Pure business logic — no I/O, no framework imports
    │   ├── scope.py           #   target validation (Validation value object)
    │   ├── scope_policy.py    #   scope policy matching, exclusions
    │   ├── leads.py           #   LeadSpec + connector lead extraction
    │   ├── prioritization.py  #   lead group scoring
    │   ├── triage.py          #   standalone lead triage API
    │   ├── exposure_rules.py  #   ExposureRule + port-based assessment,
    │   │                      #   fingerprint summary helpers
    │   ├── fingerprint.py     #   ServiceFingerprint, OsGuess, WebServerInfo,
    │   │                      #   WafSignal, CveCandidate, HostFingerprintReport
    │   ├── evidence_analysis.py  # Nmap/TCP/HTTP evidence classification
    │   ├── assessment.py      #   final assessment assembly, review worksheet
    │   └── pipeline.py        #   PipelineStep: the readable step vocabulary
    ├── shared/                # paths, clock, dict helpers (cross-layer, pure)
    └── infrastructure/        # Adapters implementing the ports
        ├── persistence/       #   SQLite repositories, evidence store, provenance reader
        ├── connectors/        #   passive OSINT connectors + runner
        ├── probes/            #   DNS, HTTP/TLS, TCP, Nmap technical checks,
        │                      #   web fingerprint, WAF detection, Nmap XML adapter
        ├── reporting/         #   Markdown/PDF renderers per step
        └── http/              #   rate-limited, caching HTTP client

Two rules are enforced by a regression test: `domain/` and `application/use_cases/` never import `infrastructure/` or `interfaces/`; application *services* may compose infrastructure adapters directly (this is why `nmap_fingerprint.py` lives under `application/services/` and the Nmap XML conversion is exposed to the use case through the `NmapXmlPort` protocol).

## Capability snapshot

The current source tree contains:

  * **10 passive OSINT connector adapters** under `reconforge/infrastructure/connectors/` (including one social-platform adapter registry that is intentionally not implemented).
  * **7 technical-reconnaissance probe modules** under `reconforge/infrastructure/probes/`:
    `dns_recon`, `http_recon`, `tcp_recon`, `nmap_recon`, `web_fingerprint`,
    `waf_recon`, and the `nmap_xml_parse` adapter.
  * **6 named workflow steps**, from engagement registration through reviewer-led assessment: `register` → `passive` → `intel` → `discover` → `analyze` → `report`. The `run` command executes the whole workflow in one invocation.
  * Local evidence storage, correlation, prioritization, Markdown/PDF reporting, and automated tests.

These are module counts, not a claim that ReconForge invokes independent third-party scanning programs. Most connectors query public web services; technical checks use Python networking, `dig`, `httpx`/`wafw00f` (when installed, with a stdlib fallback), and Nmap where configured.

## Implemented integrations and sources

### Passive OSINT connectors — `reconforge/infrastructure/connectors/`

Module | Source / integration | Current role and status
---|---|---
`dns_whois.py` | `dig`, `whois` | DNS records and WHOIS lookups; requires the corresponding system utilities
`cert_transparency.py` | crt.sh | Certificate Transparency records and hostname discovery
`rdap.py` | RDAP (`rdap.org`) | Domain registration events, nameservers, status and entity metadata
`archive.py` | Internet Archive CDX | Historical URLs and archived publication metadata
`wayback.py` | Internet Archive Wayback Machine CDX | Root-domain and subdomain historical URL discovery; wired into Discovery
`commoncrawl.py` | Common Crawl Index | Historical crawl index records; wired into Discovery
`github.py` | GitHub public REST API | Public repository search; optional `GITHUB_TOKEN` improves API access limits
`wikipedia.py` | Wikipedia MediaWiki API | Contextual public reference search
`search_provider.py` | Brave Search API / configured search provider | Optional search enrichment; requires provider configuration and API credentials
`social_sources.py` | LinkedIn, X and Facebook registry | **Adapter-only**. No scraping or login automation; calls currently raise `NotImplementedError` until an approved API or permitted source is configured

The passive runner wires DNS, WHOIS, crt.sh, Internet Archive (`archive.py`), GitHub, Wikipedia and optional configured search. Discovery separately wires wayback, crt.sh, RDAP, Common Crawl and DNS record collection. The presence of a connector file does not mean every step invokes it.

### Technical reconnaissance probes — `reconforge/infrastructure/probes/`

Module | Function | Execution conditions
---|---|---
`dns_recon.py` | Collects A, AAAA, CNAME, MX, NS, TXT, CAA and SOA DNS answers using `dig` | Used by Discovery passive enrichment
`http_recon.py` | HTTP metadata and TLS certificate inspection | Active mode and exact approved hostname required
`web_fingerprint.py` | Web server, `X-Powered-By`, technology and page-title fingerprinting via `httpx` (if installed) or a stdlib `HEAD` fallback | Active mode and exact approved hostname required; gated identically to `http_recon`
`waf_recon.py` | WAF detection via `wafw00f` (if installed) or a `Server`/`Via`/`cf-ray` header heuristic | Active mode and exact approved hostname required; **active fingerprinting may be logged or blocked by the WAF**
`tcp_recon.py` | TCP connection checks against selected ports | Active mode plus explicit authorization of the resolved IP under scope policy
`nmap_recon.py` | Nmap port discovery, service/version identification and OS fingerprint matching | Requires active mode, Nmap configuration, explicit asset approval and explicit IP/CIDR scope authorization
`nmap_xml_parse.py` | Adapter: parses retained Nmap XML into `ServiceFingerprint` and `OsGuess` domain objects | Runs after every Nmap execution; no additional authorization needed (operates on already-produced files)

Nmap preserves native `.nmap`, `.gnmap`, and `.xml` output. TCP scanning is not automatically authorized by domain ownership or hostname approval. ReconForge checks resolved IP addresses against the explicit IP/CIDR scope policy; exclusions override allow rules.

### NVD CVE candidate lookup — `reconforge/application/services/cve_lookup.py`

A **read-only external** service, invoked by the `analyze` step when `--cve-lookup` is passed. It queries the public NVD API (`services.nvd.nist.gov`) with a CPE built from each fingerprinted `product`/`version`. Results are attached to each asset's `cve_candidates` list in `analyze.json` with `status: "candidate — reviewer validation required"`.

- **No traffic ever reaches the engagement target.**
- Candidates are **leads**, never confirmed findings. They must be validated by a reviewer against vendor advisories and the actual installed build.
- Rate limit: 5 requests / 30 s without an API key; 50 / 30 s with `--nvd-api-key` (or `NVD_API_KEY` in `settings.env`).
- Lookups are deduplicated per `(product, version, cpe)` so an asset with the same service on multiple ports queries NVD once.

### Internal and cloud reconnaissance — not yet implemented

`reconforge/infrastructure/connectors/internal/` and `.../cloud/` currently contain package placeholders only. Engagement modes can represent `internal`, `cloud`, and `hybrid`, but the current source tree does **not** yet provide operational internal-network discovery, Active Directory enumeration, AWS/Azure/GCP inventory, cloud posture assessment, or cloud API integrations. These capabilities must not be represented as completed features until their modules, authorization controls, evidence handling, and tests are implemented.

## Pipeline

    Engagement registration and scope validation

                      v
           passive — Passive OSINT
      DNS / WHOIS / CT / RDAP / archives /
      Common Crawl / GitHub / Wikipedia / search

                      v
             intel — Correlation and prioritization
     Normalize -> correlate -> score -> leads

                      v
           discover — Controlled technical discovery
     Asset inventory + DNS + HTTP/TLS + web fingerprint +
     WAF + TCP + Nmap (versions and OS) + XML parse

                      v
            analyze — Evidence analysis
     Consolidate observations, gaps and provenance;
     optional NVD CVE candidate enrichment (--cve-lookup)

                      v
         report — Reviewer-led assessment
     Validate candidates -> findings -> reports

### Project layout

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

## Installation and bootstrap

### 1. System packages (Kali/Debian)

    sudo apt update
    sudo apt install -y python3 python3-venv python3-pip dnsutils whois nmap

`dnsutils` provides `dig`; `whois` provides the WHOIS client; `nmap` provides
port/service/OS discovery. All three are required for their respective probes.

### 2. Python environment

    cd ~/ReconForge
    python3 -m venv .venv
    source .venv/bin/activate
    python3 -m pip install --upgrade pip
    python3 -m pip install -r requirements.txt

### 3. Optional external probes

These are not required. The adapters fall back gracefully when the binary is
absent, but results are richer when they are installed.

    # Optional — richer web/technology fingerprinting (ProjectDiscovery httpx)
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    # Optional — richer WAF detection
    python3 -m pip install wafw00f

Confirm what is available:

    for t in nmap dig whois httpx wafw00f; do
      printf "%-10s " "$t"; command -v "$t" || echo "(missing — optional)"
    done

### 4. Local configuration

    cp config/settings.env.example config/settings.env
    chmod 600 config/settings.env

    cp config/discovery.json.example config/discovery.json
    chmod 600 config/discovery.json

    vim config/settings.env       # credentials, NVD_API_KEY if you have one
    vim config/scope.json         # allow/exclude — required before any active scan
    vim config/discovery.json     # active.enabled, nmap.enabled, approved_assets

Never commit `settings.env`, `discovery.json`, API tokens, private evidence, or
engagement-specific authorization material. An NVD API key can be placed in
`settings.env` as `NVD_API_KEY=...` and is picked up by `analyze --cve-lookup`.

### 5. Pre-flight validation (must pass before any workflow)

Run these from the project root with the virtual environment active. Any
failure here must be fixed before proceeding; none of them touch the network
or the engagement database.

    # 5a. Byte-compile everything
    python3 -m compileall -q reconforge recon.py && echo "compile OK"

    # 5b. Import every new and changed module
    python3 - <<'PY'
    mods = [
        "reconforge.domain.fingerprint",
        "reconforge.infrastructure.probes.web_fingerprint",
        "reconforge.infrastructure.probes.waf_recon",
        "reconforge.infrastructure.probes.nmap_xml_parse",
        "reconforge.application.services.nmap_fingerprint",
        "reconforge.application.services.cve_lookup",
        "reconforge.interfaces.cli.commands",
        "reconforge.interfaces.cli.composition",
        "reconforge.application.use_cases.discover_assets",
        "reconforge.application.use_cases.analyze_evidence",
        "reconforge.infrastructure.reporting.discovery_report",
        "reconforge.infrastructure.reporting.analysis_report",
    ]
    for m in mods:
        __import__(m)
        print("OK", m)
    PY

    # 5c. Architecture rule (domain/use_cases must not import infrastructure/interfaces)
    python3 -m pytest tests/ -k architecture -q

    # 5d. Lint
    python3 -m ruff check reconforge tests

    # 5e. Full offline test suite
    python3 -m pytest tests/ -q

    # 5f. CLI wiring
    python3 recon.py --help
    python3 recon.py discover --help | grep -E -- '--fingerprint-web|--waf|--probe-resolved'
    python3 recon.py analyze  --help | grep -E -- '--cve-lookup|--nvd-api-key'
    python3 recon.py run      --help | grep -E -- '--fingerprint-web|--waf|--cve-lookup|--nvd-api-key'

If every step prints OK / passes, the code is ready.

### 6. Initialize the local database

    python3 recon.py init

Expected: `Initialized database: .../output/reconforge.sqlite3`. This creates
the SQLite schema only; it does not touch the network.

## Running ReconForge

The project has a single entry point: `recon.py`. Every workflow command —
engagement setup, passive collection, active checks and the four pipeline
steps — is a subcommand of it:

    python3 recon.py <command> [options]
    python3 recon.py --help

After `pip install .` the same interface is available as the `recon` console
script (`recon discover --engagement 1`).

### Authorization model (read this before any active run)

ReconForge enforces three independent gates. All three must be satisfied
before a target is touched:

1. **Engagement registered with an authorization reference.** Use
   `recon.py register --authorization "AUTH-REFERENCE" --owner "Owner"`.
2. **Config gates enabled.** In `config/discovery.json`:
   `active.enabled = true`; `nmap.enabled = true` for Nmap;
   `active.approved_assets` must list the exact hostnames to check.
3. **Scope policy allows the address.** In `config/scope.json`, every
   IP that will be probed with TCP or Nmap must appear in `allow.ips` or
   `allow.cidrs`. Exclusions in `exclude.*` always override allow rules.

A domain or hostname approval does **not** authorize its resolved IPs for
TCP/Nmap. `--probe-resolved` is the only exception: it treats the engagement
target's own resolved IPs as approved for that run, still subject to
exclusions and the config gates above.

Web fingerprinting (`--fingerprint-web`) and WAF detection (`--waf`) are
**active** techniques gated identically to HTTP/TLS. They may be logged or
blocked by the WAF; the report records this as a limitation.

NVD CVE lookup (`--cve-lookup`) is **read-only** and never touches the
target. It depends only on the earlier `discover` step having produced
fingerprinted services with product/version data.

### Which engagement ID am I scanning?

**Never assume `--engagement 1` is the engagement you just registered.** Every
`register` call creates a new row and returns its ID; the ID is not reset
between runs and is not necessarily 1. Before running any active command:

    python3 recon.py engagements

This prints every registered engagement with its ID, target, target type,
mode, authorization reference and owner. Copy the exact ID for the target
you intend to scan, and pass **that** ID to `discover` / `analyze` / `report`.

If the engagement's authorization reference does not correspond to a real,
documented authorization for that target, register a fresh engagement with
the correct reference and use its ID. An active Nmap + WAF scan against a
target you did not intend to authorize is exactly the class of mistake the
gates exist to prevent.

### One-command workflow

`run` executes the whole engagement workflow end to end. Without
`--engagement` it registers a new engagement first; with `--engagement` it
reuses an existing one. It then runs passive collection, intel, discovery,
analysis and the reviewer-led report, stopping at the first failing step
(passive connector errors are reported but do not stop the run):

    # Register and run everything for a new engagement
    python3 recon.py run \
      --target example.org \
      --type domain \
      --mode external \
      --authorization "AUTH-REFERENCE" \
      --owner "Engagement Owner"

    # Rerun the whole workflow for an already-registered engagement
    python3 recon.py run --engagement 1

    # Include authorized active checks / Nmap in the run
    python3 recon.py run --engagement 1 --active --nmap

    # Include web/WAF fingerprinting and read-only NVD CVE lookup
    python3 recon.py run --engagement 1 --active --nmap \
      --fingerprint-web --waf --cve-lookup

    # Probe a URL across every IP it resolves to, all ports, one command
    python3 recon.py run --engagement 1 --active --nmap \
      --all-ports --probe-resolved

Useful options: `--sources` (passive connector set), `--search-query`,
`--config` (discovery config; falls back to `config/discovery.json`, then to
the shipped passive-only `config/discovery.json.example`), `--database`,
`--output-root`, `--reviewer`, `--fingerprint-web`, `--waf`, `--cve-lookup`,
`--nvd-api-key`. The command exits `0` when all steps succeed and `2` when a
step fails, printing which step stopped the run.

### Step-by-step walkthrough (recommended first run)

For a first run, execute each step explicitly so a failure is attributable:

    # 0. Bootstrap (see Installation) then:
    python3 recon.py init

    # 1. List any existing engagements so you can reuse or replace correctly
    python3 recon.py engagements

    # 2. Register the authorized engagement; note the returned ID
    python3 recon.py register \
      --target example.org --type domain --mode external \
      --authorization "AUTH-REFERENCE" --owner "Engagement Owner"

    # 3. Passive collection (no active traffic to the target)
    python3 recon.py passive --engagement <ID>

    # 4. Correlate collected intelligence
    python3 recon.py intel --engagement <ID>

    # 5. Controlled discovery; add active flags only after config + scope review
    python3 recon.py discover --engagement <ID>
    # then, once config/scope.json and config/discovery.json are approved:
    python3 recon.py discover --engagement <ID> --active --nmap --fingerprint-web --waf

    # 6. Local analysis; --cve-lookup adds unvalidated NVD candidates
    python3 recon.py analyze --engagement <ID> --cve-lookup

    # 7. Reviewer-led assessment
    python3 recon.py report --engagement <ID>

Each step writes its artifacts under `output/engagement-<ID>/<step>/`. If a
step exits with code 2, its warning names the gate that rejected the request
(config disabled, scope rejection, missing approval, or an execution error).

### Passive enrichment can be slow — use a timeout

Passive collection runs several public connectors in sequence. `wayback` and
`commoncrawl` paginate large CDX indexes and can take a minute or more each
on slow networks. If a run appears to hang at `Running passive enrichment...`,
distinguish slow from stuck with an explicit budget:

    timeout 600 python3 recon.py discover --engagement <ID> \
      --active --nmap --fingerprint-web --waf

To isolate a single slow connector, run passive collection alone with a
narrow source set:

    timeout 300 python3 recon.py passive --engagement <ID> \
      --sources dns,whois,crtsh

The last connector name printed before the timeout is the one that hung. The
active probes (HTTP/TLS, web fingerprint, WAF, TCP, Nmap) run after passive
enrichment, so a slow connector delays them but does not prevent them.

### Outputs and how to verify them

After a successful run:

    output/engagement-<ID>/
    ├── discover/
    │   ├── discover.json          # + "fingerprints" array
    │   ├── discover-report.md     # + "Fingerprint summary" section
    │   ├── discover-report.pdf
    │   └── nmap/*.xml|.nmap|.gnmap
    ├── analyze/
    │   ├── analyze.json           # + "fingerprints" with cve_candidates
    │   └── analyze-report.md      # + "Fingerprint and CVE Candidates" section
    └── report/
        ├── assessment.json
        ├── review-worksheet.json
        ├── assessment.md
        └── assessment.pdf

Quick verification that the fingerprint and CVE data landed:

    python3 - <<'PY'
    import json, os
    eid = os.environ.get("EID", "1")
    d = json.load(open(f"output/engagement-{eid}/discover/discover.json"))
    for fp in d.get("fingerprints", []):
        print("Asset:", fp["asset"])
        print("  services:", len(fp["services"]))
        print("  os:", [(o["name"], o["accuracy"]) for o in fp["os_guesses"]])
        print("  web:", [(w["url"], w["server_header"]) for w in fp["web"]])
        print("  waf:", fp["waf"])

    a = json.load(open(f"output/engagement-{eid}/analyze/analyze.json"))
    for fp in a.get("fingerprints", []):
        for c in fp.get("cve_candidates", []):
            print(fp["asset"], c["cve_id"], c["cvss_score"], c["status"])
    PY

If `discover.json` has no `fingerprints` key, discovery did not reach the
assembly step — check the console for `web fingerprint failed` /
`WAF detection failed` warnings, which are non-fatal but indicate the probe
could not reach the target. If `analyze.json` shows `cve_candidates: []` for
every asset, either no service had a version or the NVD returned nothing;
re-run `analyze --cve-lookup` (NVD rate limits are transient) with
`--nvd-api-key` set for a higher limit.

### Probing every IP a URL (or domain) resolves to

Register the engagement with `--type url` (e.g. `https://app.example.org/login`) or use a `domain` target, then add `--probe-resolved` to `discover`/`run` together with `--active`:

    python3 recon.py register --target "https://app.example.org/login" \
      --type url --mode external --authorization "AUTH-REFERENCE" --owner "Owner"

    # Passive collection records a url_resolution evidence file; active probing
    # covers the URL's hostname, HTTP/TLS, and every resolved address:
    python3 recon.py discover --engagement 2 --active --nmap --all-ports --probe-resolved

How authorization works for this flow: the engagement target itself is the basis — its hostname is added to the checked assets and every address it resolves to (A/AAAA) is approved for TCP/Nmap probing **for this run only**. Explicit exclusions (`config/exclusions.txt` and the policy's `exclude` section) still override; the scope policy, `active.enabled`/`nmap.enabled` config gates and `--active` are still required. The discovery artifact records `resolved_target_ips` with each address and its disposition (approved / excluded / unresolved) for provenance.

### Full port coverage

Port coverage has two halves:

  * **TCP — full range by design.** Every authorized Nmap run scans all 65,535 TCP ports (`-p-`) with service detection and OS fingerprinting; there is no "top ports" shortcut in the TCP inventory.
  * **UDP — opt-in and configurable.** Disabled by default. When enabled, it sweeps the configured top-N ports (default 1,000). Pass `--all-ports` (to `discover` or `run`) to sweep the entire UDP range instead — expect long runtimes; the per-host timeout (`nmap.host_timeout`, default `20m` TCP / `30m` UDP) bounds each approved asset.

    # Everything at once — passive collection, gated active checks, full TCP
    # range and the full UDP range, ending in the reviewer-ready report:
    python3 recon.py run --engagement 1 --active --nmap --all-ports

For large networks, stage the work: enumerate in-scope assets first (`discover` passive-only), approve the specific IPs you are authorized to touch in `config/scope.json`, then run the full sweep per approved asset. A fast external pre-scanner (see `docs/RECON-ROADMAP.md`) can shorten full-range sweeps on big CIDR blocks, but ReconForge itself only scans addresses the scope policy explicitly allows.

### Discovery output

    output/engagement-<ID>/discover/
    ├── discover.json
    ├── discover-report.md
    ├── discover-report.pdf
    └── nmap/
        ├── <asset>-<approved-IP>-<timestamp>-<index>-tcp.nmap
        ├── <asset>-<approved-IP>-<timestamp>-<index>-tcp.gnmap
        ├── <asset>-<approved-IP>-<timestamp>-<index>-tcp.xml
        └── <asset>-<approved-IP>-<timestamp>-<index>-udp.*  # if enabled

The structured JSON and native Nmap files are the machine-readable evidence. Nmap does not necessarily emit one XML row for every closed port; aggregate `extraports` counts are retained instead of inventing per-port records. Scan errors, timeouts, routing failures and incomplete coverage must remain visible in interpretation and reporting.

The Discovery JSON also contains a `fingerprints` array: one `HostFingerprintReport` per active asset, with `services`, `os_guesses`, `web`, `waf`, and `cve_candidates` (populated later by `analyze --cve-lookup`). The Markdown and PDF reports include a **Fingerprint summary** section that renders this data as per-asset tables.

## Analyze — Evidence analysis

The `analyze` step is local-only (plus optional read-only NVD lookups). It consolidates intel and discovery artifacts, records provenance and evidence gaps, and distinguishes completed, partial, skipped and failed collection. It does not initiate new network requests against the engagement target, and does not promote an observation into a confirmed vulnerability merely because a port is reachable or a response header is absent.

Section 8 of the analysis report (`analyze/analyze-report.md`) is an **Evidence Source Coverage** matrix: every passive connector, intel source and active probe is listed with its observation count and status, so the report's breadth is visible at a glance — Nmap is one row among many, and failed sources are marked as errors rather than silently dropped.

When `--cve-lookup` is passed, the analysis JSON gains a `fingerprints` array whose entries carry `cve_candidates` populated from the NVD. These candidates are rendered in a dedicated **Fingerprint and CVE Candidates** section of the Markdown report, clearly labelled as unvalidated leads.

    python3 recon.py analyze --engagement 1

    # With read-only NVD lookup (uses NVD_API_KEY from settings.env if set)
    python3 recon.py analyze --engagement 1 --cve-lookup

    # Override the key for this run only
    python3 recon.py analyze --engagement 1 --cve-lookup --nvd-api-key "$NVD_API_KEY"

## Report — Final assessment and reviewer-controlled reporting

The report step consolidates engagement records, intel, discovery and analysis artifacts. It is local-only: it does not scan, exploit, or make new network requests.

    python3 recon.py report --engagement 1

Optional arguments:

    python3 recon.py report \
      --engagement 1 \
      --database output/reconforge.sqlite3 \
      --output-root output \
      --reviewer "Assessment Reviewer"

Outputs:

    output/engagement-<ID>/report/
    ├── assessment.json
    ├── review-worksheet.json
    ├── assessment.md
    └── assessment.pdf

### Manual review and vulnerability classification

The first run creates `review-worksheet.json` with pending candidates from provisional Discovery findings, selected analysis observations, and — when `analyze --cve-lookup` was run — fingerprinted CVE candidates. Review the worksheet with Vim:

    vim output/engagement-1/report/review-worksheet.json

Set each candidate's `review_status` to `accepted`, `rejected`, or `deferred`, and provide a reviewer classification. A candidate may be published as a `confirmed_vulnerability` only after reviewer acceptance and completion of the required evidence, rationale, demonstrated impact, severity, and remediation fields.

Identifier and severity highlighting in the reports:

  * Discovery findings arrive with a **rule-mapped CWE** and a severity; both are highlighted (severity roll-up plus bold per-finding severity) in the analysis report and carried into the review worksheet as suggestions to validate.
  * CVE candidates from the NVD lookup arrive with their **CVE identifier**, an **NVD-sourced CVSS v3.1 score and severity**, and a one-line summary. They are labelled `candidate — reviewer validation required` and are never treated as findings until accepted.
  * A confirmed finding is published with its **CVE**, **CWE** and a **CVSS v3.1 block (score, severity, vector, source)** shown prominently — bold severity in Markdown, colored severity badges in the PDF, and a severity roll-up at the top of the findings sections.
  * You supply only the **CVSS vector**; ReconForge computes the score and severity band from it using the FIRST CVSS v3.1 specification formula (spec section 8.2). A manually supplied score that disagrees with the vector is flagged as a validation issue.

For confirmed vulnerability reporting:

  * Include a **CWE** only when the weakness classification is supported by evidence.
  * Include a **CVE** only when an applicable vulnerability identifier has been independently validated. A product/version banner alone is not sufficient.
  * Include a complete and valid **CVSS v3.1 vector** when the finding has enough technical evidence for defensible scoring. Do not derive CVSS from port exposure alone.
  * If no applicable CVE exists or one cannot be substantiated, state that clearly rather than inventing an identifier.

Intel leads remain intelligence. TCP reachability, missing headers, banners, WAF signals and provisional exposure recommendations remain observations unless independently validated. CVE candidates from the NVD lookup remain **leads** until the reviewer validates them against vendor advisories and the actual installed build. Incomplete Nmap coverage and evidence gaps must remain visible in the final report. Existing reviewer decisions are preserved when the review worksheet is regenerated; new candidates are appended.

## Extending reconnaissance with free open-source tools

`docs/RECON-ROADMAP.md` maps the free OSS ecosystem onto this codebase: passive subdomain/OSINT sources (subfinder, amass, theHarvester, urlscan.io, Shodan/Censys free tiers), archive and secrets exposure (gau, TruffleHog, gitleaks), active technical depth (httpx, whatweb, nuclei, testssl.sh, naabu/masscan, NSE scripts) and cloud enumeration — each with its exact integration point (passive connector, active probe, or analysis extension), the evidence-provenance rules every addition must follow, and a suggested adoption order.

The web fingerprint, WAF detection and NVD candidate lookup modules added in this release follow that roadmap: they are wired as discrete adapters behind application ports, they reuse the existing authorization gates, and their outputs feed the existing reviewer workflow rather than bypassing it.

## Interpretation and safety principles

  * ReconForge is for authorized assets and documented assessment scope only.
  * Passive discovery does not grant permission for active testing.
  * Domain/hostname approval does not implicitly authorize resolved IP addresses for TCP/Nmap scans.
  * Web fingerprinting and WAF detection are active techniques: they may be logged or blocked, and the report must state this.
  * WAF detection is a lead (a vendor header or a wafw00f signature), not proof that the asset is protected against any specific attack.
  * Exclusions override allow rules.
  * Nmap service/version results and CPEs are leads for manual vendor-advisory/CVE validation, not proof of exploitability.
  * NVD CVE candidates are unvalidated leads: a banner/version match is not exploitability proof, and a candidate must be validated against the exact installed build before it becomes a finding.
  * The framework does not run Nmap NSE vulnerability scripts or exploitation checks.
  * An exposed RDP, Telnet, SMB, database, Redis, VNC or Docker API listener warrants review but does not by itself prove weak authentication, data access or a vulnerability.
  * Historical URLs are not confirmed live endpoints; do not automatically request archived paths.
  * A lack of findings is not proof that an asset is vulnerability-free, especially when collection is partial or a source was unavailable.
  * The engagement ID is not stable across runs: always confirm the ID for the intended target with `recon.py engagements` before any active command.

## Testing

Run the complete test suite from the project root with the virtual environment active:

    python3 -m unittest discover -s tests -v

Or with pytest:

    python3 -m pytest