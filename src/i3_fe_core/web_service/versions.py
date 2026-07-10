"""Versions entry point factory — §4 "Versions".

Every i3 Web Service MUST implement a "Versions" entry point: an HTTPS GET
with no parameters, returning a JSON body of:

    fingerprint   MANDATORY  — vendor/build-identifier string
    versions      MANDATORY  — array of version-entry objects, each:
        major         MANDATORY  — major version integer
        minor         MANDATORY  — minor version integer
        vendor        OPTIONAL   — vendor-extension string
        serviceInfo   CONDITIONAL — present only for services that define
                      it (e.g. requiredAlgorithms for JWS-signing services
                      per §5.10/§10.539); omitted entirely otherwise.

This module is fully generic: it builds and mounts the entry point from
caller-supplied values only. No FE-specific version numbers, fingerprints,
or serviceInfo content are hardcoded here — see the LVF repo for the
values a specific service supplies.

VersionsLogEvent (§4.12.3) is a CLIENT-side event: an FE logs it for the
Versions response it receives when IT queries another Web Service, not
for calls it receives on its own Versions entry point. This module
therefore does not emit it. Inbound calls to this entry point are already
covered by the app factory's per-request AccessLogEvent middleware.
"""

from __future__ import annotations

from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


def build_version_entry(
    major: int,
    minor: int,
    *,
    vendor: str | None = None,
    service_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one conformant entry for the "versions" array (§4).

    `service_info` is CONDITIONAL — omitted from the entry entirely when
    None. Pass an explicit dict (e.g. {"requiredAlgorithms": []}) for
    services that define serviceInfo content.
    """
    entry: dict[str, Any] = {"major": major, "minor": minor}
    if vendor is not None:
        entry["vendor"] = vendor
    if service_info is not None:
        entry["serviceInfo"] = service_info
    return entry


def versions_response_body(
    fingerprint: str,
    versions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the top-level Versions response body (§4)."""
    return {"fingerprint": fingerprint, "versions": versions}


def make_versions_route(
    fingerprint_provider: Any,
    versions_provider: Any,
    path: str = "/Versions",
) -> Route:
    """Build the GET {path} route implementing the §4 Versions entry point.

    Args:
        fingerprint_provider: Either a fixed string, or a zero-arg
                              callable returning the current fingerprint
                              string (callable form lets a service reflect
                              a build id resolved at startup).
        versions_provider:    Either a fixed list[dict] (as produced by
                              build_version_entry), or a zero-arg callable
                              returning that list (callable form lets a
                              service report version info that can change
                              between requests, e.g. after fail-over, per
                              §4's note on this).
        path:                 Mount path for this Web Service's Versions
                              entry point. Defaults to "/Versions"; pass an
                              explicit path when a service's Versions entry
                              point is nested (e.g. ".../PolicyStore/Versions").

    Returns a single Starlette Route for GET {path}, to be included
    alongside a Web Service's other routes.
    """

    async def versions_endpoint(request: Request) -> JSONResponse:
        fingerprint = (
            fingerprint_provider() if callable(fingerprint_provider) else fingerprint_provider
        )
        versions = (
            versions_provider() if callable(versions_provider) else versions_provider
        )
        return JSONResponse(versions_response_body(fingerprint, versions))

    return Route(path, versions_endpoint, methods=["GET"])
