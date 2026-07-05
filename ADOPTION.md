# Adopting i3-fe-core in a Functional Element

`i3-fe-core` provides the cross-cutting requirements of NENA-STA-010.3f-2021 so
that each Functional Element (FE) only has to implement its own service logic on
top.  This guide walks through two worked examples — an LVF and an MCS — and
shows exactly what a minimal adoption looks like.

---

## What the core provides

| Concern | What you get |
|---|---|
| Identity & config | `ElementIdentity`, `CoreSettings` — typed, validated |
| NTP synchronisation | `NtpClient` with drift monitoring (§2.2) |
| ElementState event package | `ElementStateNotifier` + RFC 6446 rate filter (§2.4.1) |
| ServiceState event package | `ServiceStateNotifier` + RFC 6446 rate filter (§2.4.2) |
| SIP SUBSCRIBE/NOTIFY transport | `SipNotifier` wiring both packages, per-subscription watchdog (§2.4) |
| Logging client | `LoggingClient` with JWS hook (§4.12.3.1) |
| TLS/mTLS contexts | `make_server_ssl_context`, `make_client_ssl_context` (§2.8.1) |
| Discrepancy Reporting | `DiscrepancyReporting` — §3.7 DR web service (receive/track/resolve) + client (file DRs, rate-limited) |
| App factory | `create_app` — lifespan, `/health`, `/ElementState`, `/ServiceState`, §3.7 DR endpoints, logging middleware |
| Conformance suite | `assert_core_conformance(app, identity)` — run in your test suite |

Your FE adds its own routes via the `register_routes` callback and optionally
provides a `startup_hook` for custom initialisation.

---

## Installation

```
pip install i3-fe-core
```

The package requires Python ≥ 3.11.

---

## Worked example 1 — LVF (Location Validation Function)

LVF and ECRF share §4.3 ("Emergency Call Routing Function (ECRF) and Location
Validation Function"). The LVF's actual wire protocol is a LoST (RFC 5222) XML
query/response — validation results are returned as part of a
`findServiceResponse` message (§4.3.2.2), not a standalone JSON endpoint. The
`ValidateLocation` route below is a simplified stand-in to keep this example
short; a conformant LVF must implement the LoST XML schema, not this shape.
It has no security posture requirement of its own.

> **Two ways to consume core.** `create_app()` below is the **framework quick-start**:
> core owns the app and you hand it routes — the fastest on-ramp for a greenfield FE.
> Alternatively, use the **library pattern**: keep your own app and wire core à la carte
> (`SipNotifier`, `DiscrepancyReporting`, the state notifiers, `NtpClient`) into your own
> container. Both are supported; pick the library pattern when you already have an app or
> want looser coupling.

### `lvf/identity.py`

```python
from i3_fe_core.config.identity import ElementIdentity
from i3_fe_core.config.settings import CoreSettings

identity = ElementIdentity(
    element_id="lvf.psap.allegheny.pa.us",
    agency_id="psap.allegheny.pa.us",
    agent_id="lvf-worker-01",
    service_id="lvf.psap.allegheny.pa.us",
    service_name="LVF",
)

settings = CoreSettings(
    ntp_servers=["ntp1.esinet.example", "ntp2.esinet.example"],
    logging_service_uri="https://logging.esinet.example",
)
```

### `lvf/routes.py`

```python
from starlette.requests import Request
from starlette.responses import JSONResponse

async def validate_location(request: Request) -> JSONResponse:
    body = await request.json()
    # … your PIDF-LO validation logic …
    return JSONResponse({"valid": True})

def register_routes(app) -> None:
    app.add_route("/ValidateLocation", validate_location, methods=["POST"])
```

### `lvf/main.py`

```python
import uvicorn
from i3_fe_core.app.factory import create_app
from i3_fe_core.security.tls import make_server_ssl_context

from .identity import identity, settings
from .routes import register_routes

app = create_app(
    identity=identity,
    settings=settings,
    register_routes=register_routes,
)

if __name__ == "__main__":
    ssl_ctx = make_server_ssl_context(settings.tls)
    uvicorn.run(app, host="0.0.0.0", port=8443, ssl=ssl_ctx)
```

### `tests/test_lvf_conformance.py`

```python
from i3_fe_core.conformance.checks import assert_core_conformance
from lvf.identity import identity, settings
from lvf.routes import register_routes
from i3_fe_core.app.factory import create_app

def test_lvf_core_conformance():
    app = create_app(
        identity=identity,
        settings=settings,
        register_routes=register_routes,
        ntp_client=_FakeNtpClient(),     # test stub — no real NTP
        logging_client=_FakeLoggingClient(),
        ntp_check_interval=9999.0,
    )
    assert_core_conformance(app, identity)
```

The conformance suite verifies:
- `GET /ElementState` returns a §2.4.1-compliant body with the correct `elementId`
- `GET /ServiceState` returns a §2.4.2-compliant body
- `GET /health` returns 200 or 503 with the required fields
- The §3.7 Discrepancy Reporting web service accepts, tracks, and answers
  status/resolution polls for a probe DR (§3.7.1–3.7.3 status codes)
- All IANA registries match §10.12, §10.13, §10.18 exactly
- Timestamps carry an explicit UTC offset (§2.3)
- NTP client is wired (§2.2)

---

## Worked example 2 — MCS (MSAG Conversion Service)

An MCS exposes `PIDFLOtoMSAG` and `MSAGtoPIDFLO` (§4.4; resource paths are
`.../PidfloToMsag` and `.../MsagToPidfLo`). The standard's request/response
bodies are the XML formats defined in NENA-STA-015.10-2018, not JSON — the
JSON stub below is illustrative only.  Because it handles calls, **it MUST
implement the `emergency-ServiceState` event package** (§4.4).
`i3-fe-core` provides this automatically via `ServiceStateNotifier`; a minimal
MCS built without i3-fe-core may be missing it entirely.

### ServiceState gap note (§4.4, §4.5)

> **Per §4.4, the MCS MUST implement the `emergency-ServiceState` SIP event
> package, and per §4.5 the GCS has the identical MUST**, so that PSAP
> systems and ESRPs can monitor operational status and divert calls during
> maintenance or overload.  A minimal MCS or GCS implementation that exposes
> only its HTTP conversion/geocoding endpoints — without the SIP event
> framework — does not conform to §4.4/§4.5.  Adopting `i3-fe-core` and wiring
> `SipNotifier` closes this gap automatically for both: the notifier subscribes
> to both `ElementStateNotifier` and `ServiceStateNotifier` at construction
> time and forwards state changes to all SIP subscribers. A GCS is wired
> identically to the MCS example below — swap `PIDFLOtoMSAG`/`MSAGtoPIDFLO`
> for `Geocode`/`ReverseGeocode` (§4.5.1, §4.5.2).

### `mcs/identity.py`

```python
from i3_fe_core.config.identity import ElementIdentity
from i3_fe_core.config.settings import CoreSettings

identity = ElementIdentity(
    element_id="mcs.psap.allegheny.pa.us",
    agency_id="psap.allegheny.pa.us",
    agent_id="mcs-worker-01",
    service_id="mcs.psap.allegheny.pa.us",
    service_name="MCS",
)

settings = CoreSettings(
    ntp_servers=["ntp1.esinet.example", "ntp2.esinet.example"],
    logging_service_uri="https://logging.esinet.example",
)
```

### `mcs/routes.py`

```python
from starlette.requests import Request
from starlette.responses import Response

async def pidflo_to_msag(request: Request) -> Response:
    pidflo_xml = await request.body()
    # … your PIDF-LO → MSAG conversion logic …
    # conformant response is an AQS MSAG address as an XML object (§4.4.1)
    return Response(msag_xml, media_type="application/xml")

async def msag_to_pidflo(request: Request) -> Response:
    msag_xml = await request.body()
    # … your MSAG → PIDF-LO conversion logic …
    return Response(pidflo_xml, media_type="application/xml")

def register_routes(app) -> None:
    app.add_route("/PidfloToMsag", pidflo_to_msag, methods=["POST"])
    app.add_route("/MsagToPidfLo", msag_to_pidflo, methods=["POST"])
```

### `mcs/sip.py`

The SIP wire layer must be supplied by the FE (the core provides the event
framework; the actual socket is your deployment concern).

```python
def sip_send_notify(subscription, body: dict, mime_type: str) -> None:
    """Forward a NOTIFY to the subscriber URI over SIP."""
    # your SIP stack integration (e.g. pjsip, Kamailio MI, etc.)
    ...
```

### `mcs/main.py`

```python
import uvicorn
from i3_fe_core.app.factory import create_app
from i3_fe_core.security.tls import make_server_ssl_context

from .identity import identity, settings
from .routes import register_routes
from .sip import sip_send_notify

app = create_app(
    identity=identity,
    settings=settings,
    register_routes=register_routes,
    sip_send_notify=sip_send_notify,
    supports_security_posture=True,   # MCS tracks security posture
)

if __name__ == "__main__":
    ssl_ctx = make_server_ssl_context(settings.tls)
    uvicorn.run(app, host="0.0.0.0", port=8443, ssl=ssl_ctx)
```

### Driving ServiceState from your health-check logic

```python
from i3_fe_core.state.service_state import ServiceState, SecurityPosture

# In a background task or health-check callback:
app.state.i3.service_notifier.set_state(
    ServiceState.SCHEDULED_MAINTENANCE_DOWN,
    "Nightly MSAG database refresh in progress",
)
app.state.i3.service_notifier.set_security_posture(
    SecurityPosture.YELLOW,
    "Elevated address-spoofing attempts detected",
)
```

### `tests/test_mcs_conformance.py`

```python
from i3_fe_core.conformance.checks import assert_core_conformance
from mcs.identity import identity, settings
from mcs.routes import register_routes
from i3_fe_core.app.factory import create_app

def test_mcs_core_conformance():
    app = create_app(
        identity=identity,
        settings=settings,
        register_routes=register_routes,
        ntp_client=_FakeNtpClient(),
        logging_client=_FakeLoggingClient(),
        ntp_check_interval=9999.0,
        supports_security_posture=True,
    )
    assert_core_conformance(app, identity)
```

---

## Discrepancy Reporting (§3.7)

Every FE MUST provide the Discrepancy Reporting web service (§3.7).
`create_app()` mounts the four §3.7.1–3.7.3 resources automatically —
`POST /Reports`, `POST /Resolutions`, `GET /Resolutions`,
`GET /StatusUpdates` — so a minimal FE is conformant out of the box.
For production you should pass your own component with a real contact
jCard and hooks:

```python
from i3_fe_core.discrepancy.service import DiscrepancyReporting

async def on_report(report):
    """Alert operators — humans usually act on DRs (§3.7)."""
    await ticketing.open_ticket(
        summary=f"{report.report_type} from {report.reporting_agency_name}",
        severity=report.problem_severity,
    )

dr = DiscrepancyReporting(
    identity=identity,
    contact_jcard=["vcard", [["version", {}, "text", "4.0"],
                             ["fn", {}, "text", "Allegheny County 9-1-1"],
                             ["email", {}, "text", "noc@psap.allegheny.pa.us"]]],
    on_report=on_report,
    known_problem_services={"ECRF"},   # others → 470 "Not Ours"
)

app = create_app(identity=identity, settings=settings,
                 register_routes=register_routes, discrepancy=dr)
```

When a human resolves a DR, record it — the resolution is POSTed to the
reporter's `resolutionUri` call-back (§3.7.2) and served to
`GET /Resolutions` polls:

```python
await dr.resolve("lis.example", "dr-0001", "DiscrepancyCorrected",
                 comments="service boundary polygon corrected")
```

To file a DR against another entity (e.g. an ECRF reporting bad GIS data,
§3.7.11) — submissions of similar reports are rate-limited per the §3.7
DoS note:

```python
report = dr.build_report(
    "GISDiscrepancyReport", "Moderate",
    resolution_uri="https://ecrf.psap.allegheny.pa.us",  # our DR service base
    problem_service="GIS",
    report_specific={"problem": "Gap", "layerIds": "centerline",
                     "location": "…"},
)
result = await dr.submit(report, "https://gis.allegheny.pa.us")
```

Reports are held in process memory; persist them from `on_report` and
re-seed with `dr.restore_report()` if DRs must survive a restart.

---

## Extending the LogEvent prologue

For FE-specific log event types, subclass `LogEventPrologue`:

```python
from dataclasses import dataclass, field
from i3_fe_core.logging.logevent import LogEventPrologue

@dataclass
class ValidateLocationLogEvent(LogEventPrologue):
    log_event_type: str = field(default="ValidateLocationEvent", init=False)
    validate_result: str | None = None    # "Valid" | "Invalid" | "Error"
    input_profile: str | None = None     # e.g. "civic" | "geodetic"
```

`prologue_to_dict()` (called inside `LoggingClient.emit()`) serialises all
dataclass fields — including those added by subclasses — using `to_i3_json_key()`
for camelCase output.

---

## Conformance checklist

After wiring your FE, run:

```
pytest tests/ -k conformance -v
```

A green run means the endpoints, NOTIFY bodies, IANA registries, NTP wiring, and
timestamp format all satisfy the cross-cutting requirements of
NENA-STA-010.3f-2021 that i3-fe-core enforces.

For requirements your FE adds beyond the core (e.g. the `ValidateLocation`
response body schema for an LVF), add additional assertions to your test module.
