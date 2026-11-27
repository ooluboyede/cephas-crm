# CEPHAS CRM — Gate 0.1.6 Dependency and CI governance
Status: Proposed; documentation automation only; no application or production acceptance.
Baseline: 62ce930c88ce7ac9dabd78c64e6b59fdc5ee512e (PR #1).
Traceability: ADR-0008; Gate 0.1.3 A01/A08; Gate 0.1.4 D06/TM-10; Gate 0.1.5 B01–B14.

## Q01 — Candidate compatibility matrix (not a lock)
Initial target Linux amd64, Ubuntu 24.04 CI runner, Python 3.14, PostgreSQL 18, Node.js 24 LTS, Next.js 16, SQLAlchemy 2.x, Docker Compose v2. FastAPI, Alembic, psycopg, cryptography, TypeScript, React and testing tools must be selected as mutually compatible exact releases. Do not claim support for a version combination before testing it. Review upstream support and advisories at lock creation; security-patched minor versions required. Python 3.14 dependency wheels and PostgreSQL pgcrypto feasibility require proof. Redis/Celery, Kubernetes, other architectures, other DB major versions and external AI providers deferred until separate qualification. Use customer-controlled identity provider; exact profile pending.
Upstream references checked 2026-11-27:
- https://devguide.python.org/versions/
- https://www.postgresql.org/support/versioning/
- https://nodejs.org/en/about/previous-releases
- https://nextjs.org/support-policy

## Q02 — Locking and supply chain
Use pyproject.toml and uv.lock with pinned uv version, Python runtime and frozen installation; npm package-lock.json, pinned Node/npm and npm ci for frontend. No unrestricted resolution during ordinary CI or release. Lock all direct/transitive production and development dependencies, verify integrity hashes, restrict registries, audit lock changes and disallow unreviewed Git/URL sources. Use OCI base images pinned by digest, record platform and exact DB image, tool versions and runner image metadata. No fabricated locks: generate with actual resolver on supported platform, verify clean frozen install and test compatibility. Define offline mirrored package/image bundle and inventory before customer release. Group routine updates into reviewed PRs; security updates expedited and revalidated.

## Q03 — Current executable foundation checks
Workflow validates all 19 required foundation, ADR and gate files as tracked regular nonempty Markdown documents with headings; checks actual PR merge-result diff against event base or push before/after commit, records checked and PR head SHAs; rejects unresolved/missing commit ranges. Full history checkout; read-only token; credential persistence disabled; fixed runner label, 5-minute timeout; superseded runs cancelled per PR or branch. PR merge-result checkout tests the proposed integrated tree, not merely the PR head; record both SHAs. Checkout pinned to upstream v6.1.0 commit d23441a48e516b6c34aea4fa41551a30e30af803 (https://github.com/actions/checkout/commit/d23441a48e516b6c34aea4fa41551a30e30af803). Review action update diffs and maintain immutable pins. This is a document presence/format and whitespace gate, not a semantic ADR validator or security test. Do not skip the required check using path filters.

## Q04 — Future mandatory implementation checks
| Check | Proposed tool or mechanism | Blocking criterion |
|---|---|---|
| Formatting/lint | Ruff, ESLint | clean |
| Types | Mypy, TypeScript tsc | clean |
| Unit/API | Pytest | all required tests pass |
| DB migration | Alembic with real PostgreSQL | fresh install and supported upgrade, schema/role inventory |
| Boundary | PostgreSQL normal API/worker role | B01–B14; no unauthorized data or side effects |
| Licence | Pytest + fixed public test vectors | invalid/expired/wrong-scope/tampered inputs denied |
| Secrets | Gitleaks or equivalent | confirmed secrets block; rotate exposed credentials |
| Dependencies | pip-audit, npm audit or approved offline advisory mirror | high/critical findings block unless formal time-bound exception; scanner failures block |
| Static security | Bandit or equivalent | high-confidence high/critical findings block |
| Container | Trivy or equivalent | image digest scanned; high/critical findings block |
| Browser | Playwright | critical flows pass when UI exists |
| SBOM | CycloneDX/SPDX via reviewed tooling | complete dependency and image inventory tied to artifact digest |
| Provenance/signing | signed OCI digest and provenance, offline verification | independently verify trust chain and artifact identity |
Tools are proposed and not yet installed or run. Pin tools before implementation. Separate expected negative tests from scan failures; absence of test execution cannot count as pass. No continue-on-error or ignored exit status for mandatory checks. No live customer data, signing private keys or production credentials in CI.

## Q05 — Cost-aware execution
Local preflight mirrors CI before push. Batch related changes into one atomic commit; cancel superseded PR runs. Start with fast checks; one PostgreSQL job executes migrations and boundary tests in same isolated environment; reuse locked dependency caches keyed by OS/runtime/lock hash; no secret cache or untrusted cache in signing. Avoid redundant push and PR runs for topic branches. Run full browser/container/release matrix at required milestone and release, never skip an applicable required security test solely for cost. Investigate actual failure before rerunning; no routine blind retries. Measure job minutes and queue time.

## Q06 — Repository and release governance
Require reviewed PR, exact current head/base evidence, required status checks, stale review dismissal and restricted protected-branch writes; no bypass except explicitly authorized emergency procedure. CODEOWNERS and approval authorities need confirmed identities. Workflow changes require review because PR code can change its own checks; required checks alone are not an independent trust boundary. Verify repository ruleset/protection and available private-repo plan capabilities before claiming enforcement. Separate PR untrusted execution from release signing; no pull_request_target execution of untrusted code, no signing keys in CI. Use protected release approval and CEPHAS-controlled signing custody, separate from licence signing. Include source SHA, build environment, dependency lock hashes, SBOM, artifact digests, test results, scan timestamp/advisory version, signature/provenance and rollback instructions in release evidence; customer offline verification must work without mandatory egress.

## Q07 — Gate acceptance and sequence reconciliation
Original GATE_0_1_ACCEPTANCE.md uses 0.1.1–0.1.10 as work-package IDs; subsequent engineering gate labels are iterations, not substitutes for those deliverables. Original 0.1.6 offline licensing, 0.1.8 API standards, 0.1.9 deployment blueprint, ERD/policy inventory, and review record still require completion. Original Gate 0.1 demands demonstrable DB isolation before closure; do not weaken this silently. Either authorize a narrowly scoped disposable boundary proof within Gate 0.1, or record an explicit approved exception permitting only that proof at Gate 0.2 entry; no CRM domain features until proof passes. Gate 0.1.7 review preparation must reconcile numbering and complete outstanding design work before independent review; approval authority and review remain pending. This iteration does not lock dependencies, implement application security checks, configure branch protection or certify production. Required evidence: workflow run against exact change, reviewed compatibility matrix/lock plan, explicit blocker register and approval of later implementation test requirements.
