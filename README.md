# i3-fe-core

Shared Python library implementing the cross-cutting requirements of
**NENA-STA-010.3f-2021** that every i3 Functional Element (FE) must satisfy.
Individual FEs — ECRF, LVF, MCS, GCS, MDS — import this package and supply
only the pieces that are unique to them (routes, domain logic, feature-specific
config).

---

## Standard-section coverage

| Module | Standard section(s) | Topic |
|---|---|---|
| `i3_fe_core.config` | §2.1 | FE identity |
| `i3_fe_core.time` | §2.2, §2.3 | NTP synchronisation, timestamp format |
| `i3_fe_core.state` | §2.4.1, §10.13, §2.4.2, §10.12, §10.18 | ElementState, ServiceState, StateStore interface |
| `i3_fe_core.notify` | §2.4 (RFC 6665, RFC 4661, RFC 6446) | SIP SUBSCRIBE/NOTIFY state transport |
| `i3_fe_core.discrepancy` | §3.7, §3.7.1–§3.7.3 | Discrepancy Reporting web service + client |
| `i3_fe_core.logging` | §4.12.3.1 | LogEvent prologue |
| `i3_fe_core.security` | §2.8 | HTTPS/TLS, mTLS |
| `i3_fe_core.runtime` | — | Worker model, leader gate |
| `i3_fe_core.app` | — | Application factory, lifecycle |
| `i3_fe_core.conformance` | — | Pytest conformance helpers |

---

## Design rules

1. **Identity-agnostic core.** No hardcoded environment-variable prefix or
   service name lives in this package. Each FE instantiates a config object
   (derived from the base schema in `config/`) and passes it into the app
   factory. This lets ECRF and LVF coexist in the same process space during
   testing without variable collisions.

2. **IANA registry citations are mandatory.** Every value that maps to an IANA
   registry (SIP event packages, media types, URI schemes, port numbers, …)
   must include a comment citing the exact registry section — e.g.,
   `# IANA SIP Event Package: urn:ietf:params:sip-event:…`. This makes
   audits straightforward and catches registry drift during upgrades.

3. **FEs own their routes; the core owns lifecycle.** `app.create_app()` sets
   up the Starlette application, wires startup/shutdown hooks (NTP sync, TLS
   load, state initialisation, log-service handshake), and then calls a
   caller-supplied `register_routes(app)` hook. FEs never touch lifecycle
   ordering.

4. **Single-worker by default, multi-worker by design.** The runtime defaults
   to a single uvicorn worker, but process singletons (NTP sync loop, state
   publisher) sit behind a `LeaderGate` abstraction. Authoritative mutable
   state is accessed through a `StateStore` interface. Switching to a
   multi-worker gunicorn deployment is therefore a configuration change
   (swap the in-process `LeaderGate` for a Redis-backed one; swap the
   in-memory `StateStore` for a Redis or Postgres one) — not a code rewrite.

---

## Installation

```bash
pip install -e ".[dev]"
```

Requires Python ≥ 3.11.

---

## Continuous Integration

GitHub Actions (`.github/workflows/ci.yml`) runs on every push and pull
request, across Python 3.11 and 3.12:

- **tests** — `pytest -q`
- **bandit** — static security analysis of `src/`, medium+ severity only
- **pip-audit** — checks installed dependencies for known vulnerabilities
- **secrets** — [gitleaks](https://github.com/gitleaks/gitleaks-action) scan of the full git history

Run the same checks locally:

```bash
pip install -e ".[dev]"
pytest -q

pip install -e ".[security]"
bandit -r src/ -ll
pip-audit .
```

`pip-audit .` resolves dependencies straight from `pyproject.toml` rather than
scanning whatever happens to be installed in your environment — this avoids
false positives from stale packages or from pip-audit's own dependencies.
