"""app — application factory and lifecycle management.

FEs call create_app(), supply their own routes via a registration hook,
and let this package own startup/shutdown ordering (NTP sync, TLS load,
state init, log-service handshake).
"""
