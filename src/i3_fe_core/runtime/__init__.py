"""runtime — worker model and leader gate.

The core is single-worker by default but never assumes single-worker.
Process singletons (NTP sync, state publisher) sit behind a leader gate
so that adding gunicorn workers later is a configuration change, not a
code change.
"""
