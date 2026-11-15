# ReconForge Refactoring Notes

This pass refactored the entire codebase for clarity, consistency and
correctness while preserving all documented behavior. **All 60 pre-existing
tests pass unmodified**; 17 new regression tests pin the bug fixes (77 total,
`python3 -m unittest discover -s tests` or `python3 -m pytest`).

## 1. Bugs fixed

| # | Location | Problem | Fix |
|---|---|---|---|
| 1 | `core/stage4.py` | When `tcp_ports` was missing from `stage4.json`, the default value was the *string* `"1-65535"`, which `tcp_recon.collect()` iterated character by character and crashed on `int("-")`. | Default is now `list(tcp_recon.DEFAULT_PORTS)`; missing key = conservative default set. |
| 2 | `modules/external/tcp_recon.py` | `ports or DEFAULT_PORTS` silently replaced an *explicitly configured empty* port list with the default set (i.e. you could not disable TCP checks by config). | Only `None` falls back to defaults; `[]` checks nothing. |
| 3 | `core/stage4.py` | `--nmap` without `--active` was rejected only *after* passive collection had already run (network requests issued, evidence written). | Argument gate moved before any work; returns exit code 2. |
| 4 | `core/stage6.py` | A Stage 4 artifact missing `engagement_id` crashed with an uncaught `TypeError` (traceback instead of a clean error). | Explicit `ValueError` with a clear message, caught by the CLI error handler. |
| 5 | `core/cli.py` | (introduced & caught during refactor review) handler dispatch passed `(args, settings)` to every command but two handlers only accepted `(settings)`. | Uniform handler signature. |
| 6 | `modules/osint/commoncrawl.py` | `import json` / `from urllib.parse import urlparse` executed *inside loops*. | Moved to module level; parsing split into `_parse_records()`. |
| 7 | `core/http_client.py` | An invalid JSON response was written to the cache *before* parsing, so every later retry hit the poisoned cache and failed identically. | JSON is parsed before the response is cached; a malformed body is never persisted. |
| 8 | `core/stage5.py` | Redundant boolean clause in the Nmap host-timeout detection (`(A and B) or B or C`). | Simplified to `B or C` (identical semantics). |
| 9 | `core/evidence.py` | `add_lead()` opened a *new database connection and re-ran the schema script* for every single lead — hundreds of times per run. | New bulk `add_leads()` (single connection, single `executemany` transaction); `add_lead()` retained as a thin wrapper. |
| 10 | `core/scope_policy.py` | Policy/exclusion files were re-read from disk on *every* asset check inside loops. | `is_in_scope()` accepts preloaded `policy=` / `exclusions=` keyword arguments; loop callers (`asset_inventory`, `correlation`, `stage4`) load once per run. |
| 11 | `modules/external/tcp_recon.py` / `core/stage4.py` | Politeness delay was applied *after the last* port/host as well (pure dead wait). | Delay applies between attempts only. |
| 12 | `core/stage3.py` | `intelligence_report.generate_report()` re-ran `prioritize()` on data that Stage 3 had already prioritized (double scoring work). | Report accepts an already-prioritized result and prioritizes only when needed. |

## 2. Duplicates removed

- **`load_json` / `safe_dict` / `safe_list` / `get_path` / `utcnow`** were
  copy-pasted across `core/stage5.py`, `core/stage6.py` and `core/stage4.py`.
  They now live once in `core/jsonio.py`, `core/utils.py` and `core/db.py`.
- **Lead extraction**: ~100 near-identical lines in `core/osint_runner.py`
  and `core/stage4.py` (crt.sh hostnames, archive/wayback URLs, Common Crawl
  records, GitHub, Wikipedia, search results) are replaced by a single
  declarative mapping in `core/lead_extraction.py` (`LEAD_SPECS` +
  `record_connector_leads()`). Confidence/relevance/source per connector are
  now defined in exactly one place.
- **Archive CDX query**: `modules/osint/archive.py` and
  `modules/osint/wayback.py` both re-implemented the Internet Archive CDX
  request. `wayback.query_cdx()` is now the single implementation;
  `archive.collect()` delegates with its own field selection.
- **dig/whois subprocess boilerplate**: `dns_whois._run()` and
  `dns_recon.query()` duplicated `subprocess.run` handling with different
  truncation limits. Shared helper in `core/commands.py` (argument-list
  invocation only, hard timeout, output truncation).
- **Engagement fetch SQL**: three copies of the
  `SELECT target, target_type, mode FROM engagements` query (correlation,
  asset inventory, stage 4) replaced by `core.db.fetch_engagement()` /
  `get_engagement()`; registration and listing moved from inline CLI SQL
  into `db.register_engagement()` / `db.list_engagements()`.
- **PDF styling**: the Stage 4 and Stage 6 PDF generators each duplicated
  the same palette, six paragraph styles and the zebra-striped table style.
  Shared now in `reports/pdf_common.py` (`build_styles()`, `make_table()`,
  `para()`, `footer_text()`). Section helpers in `pdf_report.py` were split
  into named functions and receive the stylesheet explicitly.
- **Markdown escaping**: `md()` in `stage5_report.py` and `_md()` in
  `stage6_report.py` remain per-module but the report modules now expose a
  consistent API (`generate_markdown` / `generate_pdf` with backward
  compatible aliases `generate` / `generate_report`).
- **Host normalization**: `asset_inventory.extract_host()` duplicated
  `scope_policy.normalize()`; inventory now uses `normalize()` directly.
- **Path resolution / project root**: `ROOT = Path(__file__).parents[1]` and
  four different inline "make absolute" blocks replaced by
  `core/paths.py` (`PROJECT_ROOT`, `resolve_path()`, `DEFAULT_DATABASE`,
  `DEFAULT_OUTPUT_ROOT`).
- **User-Agent versions**: "ReconForge/0.2" vs "ReconForge/0.6" vs packaging —
  single `core.__version__` (0.7.0) feeds `http_client.USER_AGENT`, used by
  all connectors including `http_recon`.
- **JSON dump formatting**: repeated `json.dumps(indent=2, ensure_ascii=False)`
  blocks replaced by `core.jsonio.write_json()`.

## 3. Code health (PEP 8 / community best practices)

- Removed the pervasive double-blank-line formatting artifact across every
  file; normalized to standard 4-space/PEP 8 layout.
- Added type hints throughout `core/`, `modules/` and `reports/`.
- Replaced the long `if target_type == ...` chain in `core/scope.py` with a
  validator dispatch table; regexes are precompiled module constants.
- `core/recommendations.py`: exposure rules are now a `dict[int, ExposureRule]`
  dataclass table instead of anonymous 6-tuples; findings construction split
  into `_exposure_finding()` / `_version_finding()`.
- `core/prioritization.py`: magic numbers (score weights, recency bands,
  priority thresholds) lifted to named constants.
- `core/decision_engine.py` kept: it is a distinct standalone triage API
  (rule weights + next-action routing), not a duplicate of
  `prioritization.score_correlated_lead`; its docstring now says so.
- `core/stage6.py`: the three near-identical review-candidate dict literals
  are built by one `_review_candidate()` factory; CVSS validation extracted
  into `_cvss_validation()`.
- Section-split report builders (`pdf_report.py`) and report modules
  (`stage4_report.py`, `stage5_report.py`) restructured into small named
  functions; `stage5_report` now returns the output path like the others.
- All stage CLIs return process exit codes and catch
  `FileNotFoundError`/`ValueError`/`OSError`/`PermissionError` instead of
  dumping tracebacks (previously only stages 5/6 did).
- Stage 4 `run_active()` decomposed into `_select_active_assets()`,
  `_classify_addresses()` and `_active_check_for_host()`; stage 4 passive
  task wiring extracted into `_passive_tasks()`.
- Import order normalized per PEP 8 / isort across all modules.

## 4. Project hygiene

- **Removed**: stale `README.md.bak`, `core/stage4.py.bak`,
  `reports/pdf_report.py.bak`; `config/scope.yaml.example` and
  `config/sources.yaml.example` (templates for YAML features no code reads —
  misleading); `.idea/`, `.venv/`, `.pytest_cache/`, `__pycache__/`,
  committed `output/` evidence, logs and the local `config/settings.env`,
  `config/scope.json`, `config/stage4.json` (all gitignored user-local
  files; the `.example` templates remain).
- **Added** `pyproject.toml`: packaging metadata, dependencies
  (`reportlab`), dev extras (`pytest`, `ruff`), pytest and ruff
  configuration.
- **Added** root `conftest.py` so `pytest` works without per-file
  `sys.path` hacks (three test files carried redundant path inserts).
- **Added** `.pytest_cache/`, `.ruff_cache/`, `.vscode/`, `*.bak` to
  `.gitignore`.
- README: project layout and testing sections updated for the new files.

## 5. Intentional behavior notes (no silent changes)

- `recon.sh`, all CLI commands, stage arguments, output JSON shapes,
  report content, and the scope-policy decision order (exclusions first,
  then allow rules) are unchanged.
- Stage 4 still records a failed connector as `{"error": ...}` inside
  `passive` (Stage 2 keeps its separate `errors` map), preserving the
  existing `stage4.json` shape.
- PDF style values for the Stage 6 report were unified with the shared
  style factory (title 23pt/28 leading etc. instead of 22/27) — a cosmetic
  normalization; both PDFs render the same sections and tables.
- Report generators keep their historical entry-point names as aliases, so
  external callers of `generate` / `generate_report` keep working.

## 6. Single entry point (v0.7.1)

Follow-up pass after review feedback ("do we need all these stage files?"):
the project now has **one definitive entry point**, `recon.py`.

- **Added** root `recon.py` — the launcher for every workflow command.
  `python3 recon.py <command>` covers `init`, `validate`, `register`,
  `engagements`, `passive` and `stage3`-`stage6`. Packaging exposes the
  same interface as the `recon` console script
  (`[project.scripts] recon = "core.cli:main"`).
- **Removed** `core/stage3.py`: its only content was CLI glue over
  `core.correlation` + `core.prioritization`; the handler now lives in
  `core.cli` (`recon stage3`).
- **Removed** `build_parser` / `main` / `__main__` from `core/stage4.py`,
  `core/stage5.py` and `core/stage6.py`. All argument parsing is owned by
  `core.cli.build_parser()`; the stage modules are import-only libraries
  (`run_active`, `build_stage5`, `build_stage6`, ...). Their unused
  imports were pruned accordingly.
- **Removed** `recon.sh`: the launcher only set `PYTHONPATH` to the script
  directory, which Python already does for `recon.py`; it also duplicated
  `logs/` creation that `configure_logging()` performs.
- Stage subcommand options, defaults, exit codes and stdout messages are
  identical to the previous `python3 -m core.stageN` behavior; the artifact
  chain (`stage3/intelligence.json` → `stage4.json` → `stage5.json` →
  `stage6-review.json`) is unchanged.
- Tests updated to drive the stages through `core.cli.main()`; two new
  regression tests pin the single-entrypoint contract (subcommands
  registered, stage modules expose no CLI, `core.stage3` import fails).
  79 tests total, all passing; `ruff check .` clean.
- README rewritten around `recon.py`; `requirements.txt` and packaging
  metadata unchanged except the version bump and console script.
- **Deployment check follow-ups** (found while verifying `pip install .`
  in a clean venv): Stage 4's Markdown/PDF report imports moved from
  `core.cli` module level into `_cmd_stage4`, so the core CLI
  (`--help`, `init`, `validate`, `register`, `engagements`, `passive`,
  `stage3`, `stage5`) again imports without `reportlab`; only the
  PDF-emitting stages need it. `project.license` switched to the SPDX
  string form (`LicenseRef-Proprietary`) to clear the setuptools
  deprecation warning. `build/` added to `.gitignore`.
- Deployment model: the tool runs from its source tree (all relative
  paths anchor at the tree root via `core/paths.py`), so the supported
  install is "extract, venv, `pip install -r requirements.txt`, run
  `python3 recon.py`". A `pip install .` console script works but writes
  relative paths into the install location unless absolute
  `--database` / `--output-root` / `--output-dir` / `DATABASE_PATH`
  values are supplied.

## 7. Clean architecture and readable names (v0.8.0)

Review feedback: "stage 4, stage 3 etc. are not readable standard names"
and "use classes and reusable OOP artifacts; classes should not be so
big". The whole tree was reorganized into a layered `reconforge/`
package with small, injected classes.

### 7.1 Readable names replace the stage numbering

| Old | Command | Artifacts (under `output/engagement-<ID>/`) |
|---|---|---|
| stage 3 | `intel` | `intel/intel.json`, `intel/intel-report.md` |
| stage 4 | `discover` | `discover/discover.json`, `discover-report.md/.pdf`, `discover/nmap/` |
| stage 5 | `analyze` | `analyze/analyze.json`, `analyze/analyze-report.md` |
| stage 6 | `report` | `report/assessment.json`, `report/review-worksheet.json`, `assessment.md/.pdf` |

The vocabulary moved consistently through JSON keys
(`stage3_correlated_leads` → `intel_correlated_leads`, `stages` →
`steps`, `stage4_provisional_finding` → `discovery_provisional_finding`),
config (`config/stage4.json` → `config/discovery.json`), evidence source
labels (`stage4-<connector>` → `discover-<connector>`), report modules
(`stage4_report.py` → `discovery_report.py`, ...) and error messages
(`Stage 4 error:` → `Discovery error:`). `PipelineStep`
(`reconforge/domain/pipeline.py`) is the single vocabulary source.

### 7.2 Layered package layout

`core/`, `modules/` and `reports/` were folded into `reconforge/`:

- `reconforge/domain/` — pure logic: scope, scope policy, leads,
  prioritization, triage (was `decision_engine.py`), exposure rules (was
  `recommendations.py`), evidence analysis (was `stage5.py`), assessment
  (was `stage6.py`), pipeline vocabulary. No I/O imports.
- `reconforge/application/` — one use-case class per command
  (`use_cases/`, 20-120 lines each, constructor-injected dependencies),
  services (correlation, asset inventory, discovery), `ports.py`
  protocols (EngagementRepository, LeadRepository, ArtifactStore,
  Console, renderers, AssessmentContext), `settings.py` (frozen
  Settings), `workspace.py` (WorkspaceLayout/EngagementLayout value
  objects that own every artifact path).
- `reconforge/infrastructure/` — adapters: SQLite engagement repository
  (new class wrapping `database.py`), `EvidenceStore` (lead/evidence
  port adapter), `AssessmentContextReader` (DB metadata + SHA-256
  provenance, extracted from the assessment domain), `OsintRunner`
  class, `HttpClient`, connector/probe modules, per-step renderer
  classes, `subprocess_tools` (was `commands.py`).
- `reconforge/interfaces/cli/` — `app.py` (parser from the command
  registry, dispatch, logging), `commands.py` (nine small command
  classes mapping argparse → use case → exit code), `composition.py`
  (Container composition root), `config.py` (SettingsLoader),
  `console.py` (Console adapter).
- `reconforge/shared/` — `paths.py` (PROJECT_ROOT anchor),
  `clock.py` (`utcnow`, extracted from `database.py` so domain stays
  pure), `utils.py`.

Layering rules, enforced by a regression test: `domain/` and
`application/use_cases/` must not import `infrastructure/` or
`interfaces/`. Application services may compose infrastructure adapters
directly (documented pragmatic boundary).

### 7.3 Behavior notes

- CLI options, defaults, exit codes and artifact *content* are
  preserved; only names changed as listed above. Error message prefixes
  follow the new command names.
- "Engagement does not exist." is now the single consistent message for
  a missing engagement (previously `passive` printed "Engagement not
  found." and discovery "Stage 4 error: Engagement does not exist.").
- Console progress lines are produced by use cases through the Console
  port; commands print final JSON results.
- Tests: renamed with the pipeline (`test_stage5.py` →
  `test_analysis.py`, etc.), updated to the class-based services
  (`ActiveCheckRunner().run(...)` instead of `run_active(...)`), plus a
  new `ArchitectureTests` group pinning the command registry, the
  absence of CLI code in pipeline modules and the layering rule. 80
  tests pass; `ruff check .` is clean.
- Packaging: `pyproject.toml` ships the `reconforge*` package, console
  script `recon = "reconforge.interfaces.cli.app:main"`, version 0.8.0.

## 8. One-command pipeline (v0.8.1)

Review feedback: "run the whole processes with one command". The `run`
command executes the entire engagement workflow in a single invocation.

- `RunEngagementPipeline`
  (`reconforge/application/use_cases/run_pipeline.py`) composes the step
  use cases through constructor injection: register (or reuse via
  `--engagement`) -> passive -> intel -> discover -> analyze -> report.
  It stops at the first failing step and reports which step failed;
  passive connector errors are warnings only, matching the `passive`
  command's semantics. `PipelineRunResult` exposes per-step
  `StepOutcome`s plus `ok` / `stopped_at`.
- `RunCommand` (`interfaces/cli/commands.py`) maps argparse to the
  request: registration fields or `--engagement`, passive `--sources` /
  `--search-query`, discovery `--config` / `--active` / `--nmap` (same
  authorization gates as `discover`), `--database`, `--output-root`,
  `--reviewer`. If no discovery config exists, it falls back to the
  shipped passive-only `config/discovery.json.example`. Exit codes: 0
  all steps succeeded, 2 a step failed or arguments are incomplete.
- `Container.run_pipeline()` wires the pipeline from the existing
  per-step factories; the parser registry and `ArchitectureTests`
  include `run`. Seven new orchestration unit tests
  (`tests/test_run_pipeline.py`) cover step order, stop-at-first-
  failure, passive error tolerance, engagement reuse/registration and
  invalid-target short-circuit. 87 tests pass; the offline smoke adds
  three `run` checks.

## 9. Coverage reporting and full-port control (v0.9.0)

Review feedback: keep per-step commands alongside `run`; document
active/passive execution; probe all ports; make the report cover all
evidence areas, not only Nmap; advise on more free OSS recon.

- **Per-step commands retained.** `run` composes the step use cases;
  `validate`, `register`, `passive`, `intel`, `discover`, `analyze`,
  `report` remain individually invokable for targeted re-runs (e.g.
  `analyze` alone re-reads the stored artifacts).
- **Evidence Source Coverage.** New `analyse_source_coverage`
  (`domain/evidence_analysis.py`) builds one row per evidence source —
  passive connectors (payload-aware observation counts, error status),
  intel correlation (per-source observation counts across leads) and
  active probes (TCP-connect, HTTP/TLS, Nmap TCP/UDP from the real
  `tcp`/`udp` aggregates) — embedded as `source_coverage` in
  `build_analysis` output. Section 8 of `analyze/analyze-report.md` is
  now the coverage matrix; gaps/review/methodology renumber to 9-11.
  Failed sources show as errors, not invisible absences.
- **Full port coverage.** TCP was already always `-p-` (all 65,535
  ports). New `--all-ports` flag on `discover` and `run` switches the
  UDP sweep from top-N (1,000 default) to the full range and enables
  UDP explicitly (`apply_full_port_override`), with runtime bounded by
  the existing `nmap.host_timeout`. Documented staged approach for
  large networks.
- **docs/RECON-ROADMAP.md.** Free OSS tooling mapped to integration
  points: passive connectors (subfinder, amass, theHarvester,
  urlscan.io, Shodan/Censys/VT free tiers), archive/secrets (gau,
  trufflehog, gitleaks), active probes (httpx, whatweb, nuclei,
  testssl.sh, naabu/masscan, NSE scripts), cloud enum — with scope,
  provenance and reviewer-gate ground rules.
- Tests: 8 new (`tests/test_source_coverage.py`) covering payload
  counting (incl. nested DNS records), intel source aggregation,
  probe-row presence rules, `build_analysis` embedding and the full-
  port override; smoke adds source-coverage checks. 94 tests pass.


## 10. URL targets, resolved-IP probing, identifier highlighting (v0.10.0)

Review feedback: probe all IPs a passed URL resolves to; highlight CVE,
CWE and CVSS3 from the findings; highlight severity.

- **`url` target type.** `validate_target` accepts full http(s) URLs
  (`domain/scope.py`), normalizing to `scheme://host[/path]`; scope
  policy routes `url` engagements through domain rules against the
  URL's hostname (`scope_policy.is_in_scope`). Discovery enrichment
  runs the passive connector set on the URL's hostname plus a dedicated
  `url_resolution` evidence record of every resolved address.
- **`--probe-resolved` (discover + run).** Requires `--active` and a
  url/domain target. `ActiveCheckRunner.resolve_probe_target` resolves
  the target's A/AAAA addresses; they are approved for TCP/Nmap for the
  run via `is_in_scope(..., extra_allow=...)` — the engagement target
  is the authorization basis, exclusions still override. Provenance is
  recorded as `resolved_target_ips` (approved/excluded/error) in
  `discover.json`. Architecture test enforced layering: resolution
  lives in the application service, not the use case.
- **CVSS v3.1 computation.** New `domain/cvss3.py` implements the FIRST
  CVSS v3.1 spec section 8.2 base-score math (verified against known
  spec vectors: 9.8, 7.5, 10.0, 6.4, 0.0). Reviewers supply only the
  vector; `build_final_assessment` computes score + severity band
  (`_apply_computed_cvss`) and flags supplied scores that disagree with
  the vector-derived score.
- **Identifier highlighting.** Analysis report findings now render
  severity (bold, uppercase, roll-up), rule-mapped CWE, CVE status
  ("No applicable CVE established" until validated) and CVSS v3.1.
  Assessment report: severity roll-up + uppercase severity in Markdown,
  colored severity badges in the PDF, source severity/CWE columns in
  the potential-findings table. Review worksheet prefills CWE from the
  discovery rule (`build_review_template`).
- Tests: 19 new (`tests/test_url_probe_cvss.py`) covering URL
  validation/scope, probe-resolved authorization + exclusion override,
  calculator spec scores/bands/errors, vector auto-compute + mismatch
  flagging, CWE prefill and report highlighting. Smoke adds URL
  validation and flag-surface checks. 113 tests pass.
